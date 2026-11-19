package classification

import (
	"math/bits"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"
)

// The detector is a port of whatlang 0.16.4: the writing system decides the language of a script
// that one language uses, Japanese kana among Chinese characters decide between Japanese and
// Chinese, and for the scripts that several languages share, letters and trigrams are compared
// with each language's profile. It reads only a sample, so it costs the same for any text.

// Undetermined is the BCP 47 tag of text whose language the detector cannot tell.
const Undetermined = "und"

// reliableConfidence is whatlang's threshold for a reliable detection. Below it the detector
// answers Undetermined, which keeps short and mixed text from a wrong label.
const reliableConfidence = 0.9

type language uint8

const (
	langEpo language = iota
	langEng
	langRus
	langCmn
	langSpa
	langPor
	langIta
	langBen
	langFra
	langDeu
	langUkr
	langKat
	langAra
	langHin
	langJpn
	langHeb
	langYid
	langPol
	langAmh
	langJav
	langKor
	langNob
	langDan
	langSwe
	langFin
	langTur
	langNld
	langHun
	langCes
	langEll
	langBul
	langBel
	langMar
	langKan
	langRon
	langSlv
	langHrv
	langSrp
	langMkd
	langLit
	langLav
	langEst
	langTam
	langVie
	langUrd
	langTha
	langGuj
	langUzb
	langPan
	langAze
	langInd
	langTel
	langPes
	langMal
	langOri
	langMya
	langNep
	langSin
	langKhm
	langTuk
	langAka
	langZul
	langSna
	langAfr
	langLat
	langSlk
	langCat
	langTgl
	langHye
	languageCount
)

// languageTags are BCP 47 tags: the two-letter ISO 639-1 code of each language.
var languageTags = [languageCount]string{
	langEpo: "eo", langEng: "en", langRus: "ru", langCmn: "zh", langSpa: "es", langPor: "pt",
	langIta: "it", langBen: "bn", langFra: "fr", langDeu: "de", langUkr: "uk", langKat: "ka",
	langAra: "ar", langHin: "hi", langJpn: "ja", langHeb: "he", langYid: "yi", langPol: "pl",
	langAmh: "am", langJav: "jv", langKor: "ko", langNob: "nb", langDan: "da", langSwe: "sv",
	langFin: "fi", langTur: "tr", langNld: "nl", langHun: "hu", langCes: "cs", langEll: "el",
	langBul: "bg", langBel: "be", langMar: "mr", langKan: "kn", langRon: "ro", langSlv: "sl",
	langHrv: "hr", langSrp: "sr", langMkd: "mk", langLit: "lt", langLav: "lv", langEst: "et",
	langTam: "ta", langVie: "vi", langUrd: "ur", langTha: "th", langGuj: "gu", langUzb: "uz",
	langPan: "pa", langAze: "az", langInd: "id", langTel: "te", langPes: "fa", langMal: "ml",
	langOri: "or", langMya: "my", langNep: "ne", langSin: "si", langKhm: "km", langTuk: "tk",
	langAka: "ak", langZul: "zu", langSna: "sn", langAfr: "af", langLat: "la", langSlk: "sk",
	langCat: "ca", langTgl: "tl", langHye: "hy",
}

type profile struct {
	lang     language
	trigrams string
}

type alphabet struct {
	lang    language
	letters string
}

type script int8

// Scripts in whatlang's order, which also breaks a tie between two scripts' counts.
const (
	scriptLatin script = iota
	scriptCyrillic
	scriptArabic
	scriptMandarin
	scriptDevanagari
	scriptHebrew
	scriptEthiopic
	scriptGeorgian
	scriptBengali
	scriptHangul
	scriptHiragana
	scriptKatakana
	scriptGreek
	scriptKannada
	scriptTamil
	scriptThai
	scriptGujarati
	scriptGurmukhi
	scriptTelugu
	scriptMalayalam
	scriptOriya
	scriptMyanmar
	scriptSinhala
	scriptKhmer
	scriptArmenian
	scriptCount
	scriptNone script = -1
)

// singleLanguage is the language of each script that only one language uses.
var singleLanguage = map[script]language{
	scriptEthiopic: langAmh, scriptGeorgian: langKat, scriptBengali: langBen, scriptHangul: langKor,
	scriptHiragana: langJpn, scriptKatakana: langJpn, scriptGreek: langEll, scriptKannada: langKan,
	scriptTamil: langTam, scriptThai: langTha, scriptGujarati: langGuj, scriptGurmukhi: langPan,
	scriptTelugu: langTel, scriptMalayalam: langMal, scriptOriya: langOri, scriptMyanmar: langMya,
	scriptSinhala: langSin, scriptKhmer: langKhm, scriptArmenian: langHye,
}

// sharedScript holds the profiles of the languages that share a script. Only Latin and Cyrillic
// have alphabets.
type sharedScript struct {
	langs []language
	// trigrams maps a trigram to each language's rank of it, by the language's index in langs.
	trigrams map[uint64][]ranked
	// letters has, for each letter, a bit for each language whose alphabet has it.
	letters *[letterRunes]uint64
	all     uint64
}

type ranked struct {
	index uint8
	rank  uint16
}

const (
	profileTrigrams = 300
	maxTotal        = profileTrigrams * profileTrigrams
	// textTrigrams is how many of a text's most frequent trigrams the comparison reads.
	textTrigrams = 2 * profileTrigrams
	// letterRunes bounds the letters of every alphabet.
	letterRunes = 0x2000
	// tableBits sizes the table that counts a sample's trigrams, one for each character and the
	// final space, so that it is at most half full.
	tableBits  = 11
	tableSlots = 1 << tableBits
)

// A table more than half full slows the probes that find a slot, and a full one never ends them.
var _ [tableSlots/2 - (SampleBytes + 1)]struct{}

// trigramKey packs three characters into 48 bits, the first highest, so that ordering keys
// orders trigrams character by character. A character outside the Basic Multilingual Plane
// takes the plane's last noncharacter, which no profile has.
func trigramKey(a, b, c rune) uint64 {
	return uint64(bmp(a))<<32 | uint64(bmp(b))<<16 | uint64(bmp(c))
}

func bmp(r rune) uint16 {
	if r > 0xFFFF {
		return 0xFFFF
	}
	return uint16(r)
}

var sharedScripts = sync.OnceValue(func() map[script]*sharedScript {
	return map[script]*sharedScript{
		scriptLatin:      newSharedScript(latinProfiles, latinAlphabets),
		scriptCyrillic:   newSharedScript(cyrillicProfiles, cyrillicAlphabets),
		scriptArabic:     newSharedScript(arabicProfiles, nil),
		scriptDevanagari: newSharedScript(devanagariProfiles, nil),
		scriptHebrew:     newSharedScript(hebrewProfiles, nil),
	}
})

func newSharedScript(profiles []profile, alphabets []alphabet) *sharedScript {
	s := &sharedScript{trigrams: map[uint64][]ranked{}}
	for i, p := range profiles {
		s.langs = append(s.langs, p.lang)
		runes := []rune(p.trigrams)
		for rank := range profileTrigrams {
			key := trigramKey(runes[3*rank], runes[3*rank+1], runes[3*rank+2])
			s.trigrams[key] = append(s.trigrams[key], ranked{uint8(i), uint16(rank)})
		}
	}
	s.all = 1<<len(s.langs) - 1
	if alphabets != nil {
		s.letters = new([letterRunes]uint64)
		for _, a := range alphabets {
			index := slices.Index(s.langs, a.lang)
			for _, r := range a.letters {
				s.letters[r] |= 1 << index
			}
		}
	}
	return s
}

// DetectLanguage returns the BCP 47 tag of the language of text's first SampleBytes, or
// Undetermined when they hold no letters or the detection is not reliable.
func DetectLanguage(text string) string {
	lang, confidence, ok := detect(cutSample(text))
	if !ok || confidence <= reliableConfidence {
		return Undetermined
	}
	return languageTags[lang]
}

// cutSample keeps at most SampleBytes of text, ending on a character boundary.
func cutSample(text string) string {
	if len(text) <= SampleBytes {
		return text
	}
	end := SampleBytes
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return text[:end]
}

func detect(text string) (language, float64, bool) {
	var counts [scriptCount]int
	for _, r := range text {
		if s := scriptOf(r); s != scriptNone {
			counts[s]++
		}
	}
	main, most := scriptNone, 0
	for s, count := range counts {
		if count > most {
			main, most = script(s), count
		}
	}
	if main == scriptNone {
		return 0, 0, false
	}
	if lang, ok := singleLanguage[main]; ok {
		return lang, 1, true
	}
	if main == scriptMandarin {
		// Kana among Chinese characters is Japanese (whatlang issue 88).
		japanese := float64(counts[scriptHiragana] + counts[scriptKatakana])
		share := japanese / (japanese + float64(counts[scriptMandarin]))
		switch {
		case share > 0.2:
			return langJpn, 1, true
		case share > 0.05:
			return langJpn, 0.5, true
		case share > 0.02:
			return langCmn, 0.5, true
		}
		return langCmn, 1, true
	}
	shared := sharedScripts()[main]
	index, confidence := shared.detect(strings.ToLower(text))
	return shared.langs[index], confidence, true
}

// detect combines the letter and trigram scores, weighting letters more in short text, and
// returns the best language's index and the confidence in it.
func (s *sharedScript) detect(lower string) (int, float64) {
	var letterScores, trigramScores, scores [64]float64
	letters := s.letterScores(lower, &letterScores)
	trigrams := s.trigramScores(lower, &trigramScores)
	weight := min(max(2.0/3.0-float64(letters)/300, 1.0/3.0), 2.0/3.0)
	best, second := -1, -1
	for i := range s.langs {
		scores[i] = letterScores[i]*weight + trigramScores[i]*(1-weight)
		// The earlier profile wins a tie.
		switch {
		case best < 0 || scores[i] > scores[best]:
			best, second = i, best
		case second < 0 || scores[i] > scores[second]:
			second = i
		}
	}
	return best, confidence(scores[best], scores[second], trigrams)
}

// letterScores scores each language by the share of the text's letters that its alphabet has,
// counting a letter outside it against it, and returns how many letters the text has. Without
// alphabets every language scores the same. Whatlang then counts one letter, which keeps the
// letter weight high for any length; counting them all lets long text rest on trigrams, as on
// other scripts, and keeps short text undetermined.
func (s *sharedScript) letterScores(lower string, scores *[64]float64) int {
	var seen [letterRunes]uint16
	var distinct []rune
	count, common := 0, 0
	for _, r := range lower {
		if stop(r) {
			continue
		}
		count++
		if s.letters == nil || r >= letterRunes || s.letters[r] == 0 {
			continue
		}
		if s.letters[r] == s.all {
			common += 2
			continue
		}
		if seen[r] == 0 {
			distinct = append(distinct, r)
		}
		seen[r]++
	}
	if s.letters == nil {
		for i := range s.langs {
			scores[i] = 1
		}
		return count
	}
	var hits [64]int
	for _, r := range distinct {
		for mask := s.letters[r]; mask != 0; mask &= mask - 1 {
			hits[bits.TrailingZeros64(mask)] += 2 * int(seen[r])
		}
	}
	for i := range s.langs {
		scores[i] = float64(max(hits[i]+common-count, 0)) / float64(count)
	}
	return count
}

// trigramScores compares the ranks of the text's most frequent trigrams with each profile and
// returns how many distinct trigrams it compared.
func (s *sharedScript) trigramScores(lower string, scores *[64]float64) int {
	var keys [tableSlots]uint64
	var counts [tableSlots]uint16
	distinct := make([]uint64, 0, 256)
	add := func(key uint64) {
		slot := key * 0x9E3779B97F4A7C15 >> (64 - tableBits)
		for keys[slot] != 0 && keys[slot] != key {
			slot = (slot + 1) % tableSlots
		}
		if keys[slot] == 0 {
			keys[slot] = key
			distinct = append(distinct, slot)
		}
		counts[slot]++
	}
	c1, c2, first := ' ', ' ', true
	read := func(c3 rune) {
		if !(c2 == ' ' && (c1 == ' ' || c3 == ' ')) {
			add(trigramKey(c1, c2, c3))
		}
		c1, c2 = c2, c3
	}
	for _, r := range lower {
		if stop(r) {
			r = ' '
		}
		if first {
			c2, first = r, false
			continue
		}
		read(r)
	}
	read(' ')
	// The count above the key orders trigrams by count and then by characters, both falling.
	for i, slot := range distinct {
		distinct[i] = uint64(counts[slot])<<48 | keys[slot]
	}
	slices.Sort(distinct)
	slices.Reverse(distinct)
	ordered := distinct[:min(len(distinct), textTrigrams)]
	unique := len(ordered)
	if unique == 0 {
		return 0
	}
	var distances [64]int
	for i := range s.langs {
		distances[i] = maxTotal
	}
	for position, entry := range ordered {
		for _, r := range s.trigrams[entry&(1<<48-1)] {
			distance := position - int(r.rank)
			if distance < 0 {
				distance = -distance
			}
			distances[r.index] += distance - profileTrigrams
		}
	}
	maxDistance := unique * profileTrigrams
	for i := range s.langs {
		distance := distances[i]
		// A short text matches at most its own trigrams, so the rest are not held against it.
		if unique < profileTrigrams {
			distance -= (profileTrigrams - unique) * profileTrigrams
		}
		distance = min(max(distance, 0), maxTotal)
		scores[i] = float64(maxDistance-distance) / float64(maxDistance)
	}
	return unique
}

// confidence is whatlang's measure of how far the best score leads the second for a text with
// count trigrams.
func confidence(best, second float64, count int) float64 {
	if best == 0 {
		return 0
	}
	if second == 0 {
		return best
	}
	confident := 3/float64(count) + 0.015
	rate := (best - second) / second
	if rate > confident {
		return 1
	}
	return rate / confident
}

// stop reports a space, digit or ASCII punctuation, which says nothing about language.
func stop(r rune) bool {
	return r <= 0x40 || r >= 0x5B && r <= 0x60 || r >= 0x7B && r <= 0x7E
}

// scriptOf returns the script of a character by whatlang's ranges.
func scriptOf(r rune) script {
	switch {
	case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
		return scriptLatin
	case r < 0x80:
		return scriptNone
	case r == 0x1D2B || r == 0x1D78:
		return scriptCyrillic
	case r <= 0x2AF || r >= 0x1D00 && r <= 0x1DBF || r >= 0x1E00 && r <= 0x1EFF || r >= 0x2100 && r <= 0x214F ||
		r >= 0x2C60 && r <= 0x2C7F || r >= 0xA720 && r <= 0xA7FF || r >= 0xAB30 && r <= 0xAB6F:
		return scriptLatin
	case r >= 0x370 && r <= 0x3FF:
		return scriptGreek
	case r >= 0x400 && r <= 0x484 || r >= 0x487 && r <= 0x52F || r >= 0x2DE0 && r <= 0x2DFF ||
		r >= 0xA640 && r <= 0xA69D || r == 0xA69F:
		return scriptCyrillic
	case r >= 0x530 && r <= 0x58F || r >= 0xFB13 && r <= 0xFB17:
		return scriptArmenian
	case r >= 0x590 && r <= 0x5FF:
		return scriptHebrew
	case r >= 0x600 && r <= 0x6FF || r >= 0x750 && r <= 0x7FF || r >= 0x8A0 && r <= 0x8FF ||
		r >= 0xFB50 && r <= 0xFDFF || r >= 0xFE70 && r <= 0xFEFF || r >= 0x10E60 && r <= 0x10E7F || r >= 0x1EE00 && r <= 0x1EEFF:
		return scriptArabic
	case r >= 0x900 && r <= 0x97F || r >= 0xA8E0 && r <= 0xA8FF || r >= 0x1CD0 && r <= 0x1CFF:
		return scriptDevanagari
	case r >= 0x980 && r <= 0x9FF:
		return scriptBengali
	case r >= 0xA00 && r <= 0xA7F:
		return scriptGurmukhi
	case r >= 0xA80 && r <= 0xAFF:
		return scriptGujarati
	case r >= 0xB00 && r <= 0xB7F:
		return scriptOriya
	case r >= 0xB80 && r <= 0xBFF:
		return scriptTamil
	case r >= 0xC00 && r <= 0xC7F:
		return scriptTelugu
	case r >= 0xC80 && r <= 0xCFF:
		return scriptKannada
	case r >= 0xD00 && r <= 0xD7F:
		return scriptMalayalam
	case r >= 0xD80 && r <= 0xDFF:
		return scriptSinhala
	case r >= 0xE00 && r <= 0xE7F:
		return scriptThai
	case r >= 0x1000 && r <= 0x109F:
		return scriptMyanmar
	case r >= 0x10A0 && r <= 0x10FF:
		return scriptGeorgian
	case r >= 0x1100 && r <= 0x11FF || r >= 0x3130 && r <= 0x318F || r >= 0x3200 && r <= 0x32FF ||
		r >= 0xA960 && r <= 0xA97F || r >= 0xAC00 && r <= 0xD7FF || r >= 0xFF00 && r <= 0xFFEF:
		return scriptHangul
	case r >= 0x1200 && r <= 0x139F || r >= 0x2D80 && r <= 0x2DDF || r >= 0xAB00 && r <= 0xAB2F:
		return scriptEthiopic
	case r >= 0x1780 && r <= 0x17FF || r >= 0x19E0 && r <= 0x19FF:
		return scriptKhmer
	case r >= 0x3040 && r <= 0x309F:
		return scriptHiragana
	case r >= 0x30A0 && r <= 0x30FF:
		return scriptKatakana
	case r >= 0x2E80 && r <= 0x2E99 || r >= 0x2E9B && r <= 0x2EF3 || r >= 0x2F00 && r <= 0x2FD5 ||
		r == 0x3005 || r == 0x3007 || r >= 0x3021 && r <= 0x3029 || r >= 0x3038 && r <= 0x303B ||
		r >= 0x3400 && r <= 0x4DB5 || r >= 0x4E00 && r <= 0x9FCC || r >= 0xF900 && r <= 0xFA6D || r >= 0xFA70 && r <= 0xFAD9:
		return scriptMandarin
	}
	return scriptNone
}
