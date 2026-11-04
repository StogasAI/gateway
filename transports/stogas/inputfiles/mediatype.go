package inputfiles

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// MediaType is what the gateway knows of an attachment's media type: the class that its part
// implies, and its full type where the part is inline. A URL or provider file ID has no bytes
// to check, so only its class is known, and a document's not even that.
type MediaType struct {
	// Class is image or audio for those parts, or the class of Value.
	Class string
	// Value is the full media type, such as image/png, or empty where it is unknown.
	Value string
}

// String names the type as an error message shows it.
func (t MediaType) String() string {
	switch {
	case t.Value != "":
		return t.Value
	case t.Class != "":
		return t.Class + "/* of unknown type"
	}
	return "unknown type"
}

// SniffChars is how much of a base64 payload Sniff reads: the 512 bytes that content sniffing
// reads, encoded.
const SniffChars = 684

// Sniff names the media type that a base64 payload's first bytes show, as browsers sniff it
// (https://mimesniff.spec.whatwg.org), without parameters. It returns text/plain for bytes with
// no binary control characters and application/octet-stream for unknown binary data, and
// nothing for a payload that is not base64. It reads at most SniffChars characters.
func Sniff(payload string) string {
	return sniff(head(payload))
}

// head decodes the first SniffChars characters of a base64 payload, or returns nothing for a
// payload that is not base64.
func head(payload string) []byte {
	prefix := payload
	if len(prefix) > SniffChars {
		prefix = prefix[:SniffChars]
	}
	data, err := base64.StdEncoding.Strict().DecodeString(prefix)
	if err != nil {
		return nil
	}
	return data
}

func sniff(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	value, _, _ := strings.Cut(http.DetectContentType(data), ";")
	return value
}

// ResolveMediaType names an attachment's media type for policy checks. kind is the part's type,
// declared its declared media type, and payload its base64 data, or empty for a URL or file ID.
// A declared type that the content contradicts fails, because neither can then be trusted: an
// image that is text, or a text file that is a PDF.
func ResolveMediaType(kind, declared, payload string) (MediaType, error) {
	class := ""
	switch kind {
	case "image_url", "input_image":
		class = "image"
	case "input_audio":
		class = "audio"
	}
	declared = strings.ToLower(declared)
	if payload == "" {
		return MediaType{Class: class}, nil
	}
	data := head(payload)
	sniffed := sniff(data)
	if sniffed == "" {
		return MediaType{}, fmt.Errorf("has invalid base64")
	}
	value := declared
	switch {
	case declared == "" || declared == "application/octet-stream":
		// Nothing declared, or only that the data is binary: the content names the type, unless
		// it is unknown binary data.
		value = ""
		if sniffed != "application/octet-stream" {
			value = sniffed
		}
	case !sniffedMatches(declared, sniffed, data):
		return MediaType{}, fmt.Errorf("declares %s, but its content is %s", declared, sniffed)
	}
	if value == "" {
		return MediaType{Class: class}, nil
	}
	valueClass, _, _ := strings.Cut(value, "/")
	if class != "" && valueClass != class {
		return MediaType{}, fmt.Errorf("is an %s part, but its type is %s", class, value)
	}
	return MediaType{Class: valueClass, Value: value}, nil
}

// sniffedMatches reports whether content sniffed as sniffed, whose first bytes are data, can be
// of the declared type. Sniffing knows few signatures, so unknown binary data matches a binary
// type unless the type has a signature that the data lacks, text matches a text type, and a zip
// archive matches the formats built on it.
func sniffedMatches(declared, sniffed string, data []byte) bool {
	switch {
	case sniffed == "application/octet-stream":
		matches, known := signature(declared, data)
		return !TextMediaType(declared) && (matches || !known)
	case strings.HasPrefix(sniffed, "text/"):
		return TextMediaType(declared) || slices.Contains(textEncodedTypes, declared)
	case declared == sniffed || slices.Contains(sniffedAliases[sniffed], declared):
		return true
	case sniffed == "application/zip":
		return zipFormat(declared)
	}
	return false
}

// signature reports whether data starts as every file of the declared type does, and whether the
// type has such a signature at all. A list that admits only images must not admit any data that
// declares image/png, so a type with a signature must show it.
func signature(declared string, data []byte) (matches, known bool) {
	prefix := func(signatures ...string) bool {
		return slices.ContainsFunc(signatures, func(s string) bool { return bytes.HasPrefix(data, []byte(s)) })
	}
	frameSync := func(mask, want byte) bool { return len(data) >= 2 && data[0] == 0xff && data[1]&mask == want }
	switch declared {
	case "image/png", "image/apng":
		return prefix("\x89PNG\r\n\x1a\n"), true
	case "image/jpeg", "image/jpg", "image/pjpeg":
		return prefix("\xff\xd8\xff"), true
	case "image/gif":
		return prefix("GIF87a", "GIF89a"), true
	case "image/webp":
		return riff(data, "WEBP"), true
	case "image/bmp", "image/x-ms-bmp":
		return prefix("BM"), true
	case "image/tiff":
		return prefix("II*\x00", "MM\x00*"), true
	case "image/x-icon", "image/vnd.microsoft.icon":
		return prefix("\x00\x00\x01\x00", "\x00\x00\x02\x00"), true
	case "image/heic", "image/heic-sequence", "image/heif", "image/heif-sequence", "image/avif":
		return ftyp(data, heifBrands), true
	case "application/pdf", "application/x-pdf":
		// Readers accept a PDF whose header follows a few other bytes.
		return bytes.Contains(data, []byte("%PDF-")), true
	case "audio/wav", "audio/wave", "audio/x-wav", "audio/vnd.wave":
		return riff(data, "WAVE"), true
	case "audio/aiff", "audio/x-aiff":
		return prefix("FORM") && len(data) >= 12 && (string(data[8:12]) == "AIFF" || string(data[8:12]) == "AIFC"), true
	case "audio/mpeg", "audio/mp3", "audio/mpeg3", "audio/x-mpeg-3":
		return prefix("ID3") || frameSync(0xe0, 0xe0), true
	case "audio/aac", "audio/x-aac":
		return prefix("ID3", "ADIF") || frameSync(0xf6, 0xf0), true
	case "audio/flac", "audio/x-flac":
		return prefix("ID3", "fLaC"), true
	case "audio/ogg", "audio/opus", "application/ogg", "video/ogg":
		return prefix("OggS"), true
	case "audio/webm", "video/webm", "audio/x-matroska", "video/x-matroska":
		return prefix("\x1a\x45\xdf\xa3"), true
	case "audio/mp4", "audio/m4a", "audio/x-m4a", "video/mp4":
		return ftyp(data, nil), true
	case "application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint", "application/vnd.ms-outlook":
		return prefix("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), true
	}
	if declared == "application/zip" || zipFormat(declared) {
		return prefix("PK\x03\x04", "PK\x05\x06"), true
	}
	return false, false
}

// riff reports whether data is a RIFF file of the form, such as WAVE.
func riff(data []byte, form string) bool {
	return len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == form
}

// ftyp reports whether data starts with an ISO base media file's ftyp box and, unless brands is
// nil, whether the box names one of them as its major or a compatible brand.
func ftyp(data []byte, brands []string) bool {
	if len(data) < 12 || string(data[4:8]) != "ftyp" {
		return false
	}
	if brands == nil {
		return true
	}
	end := min(int(binary.BigEndian.Uint32(data[:4])), len(data))
	for i := 8; i+4 <= end; i += 4 {
		// The four bytes after the major brand are its minor version.
		if i != 12 && slices.Contains(brands, string(data[i:i+4])) {
			return true
		}
	}
	return false
}

// heifBrands are the brands of HEIF images: HEIC and AVIF and their sequences.
var heifBrands = []string{"avif", "avis", "heic", "heim", "heis", "heix", "hevc", "hevm", "hevs", "hevx", "mif1", "miaf", "msf1"}

// zipFormat reports whether the type is a format built on zip archives.
func zipFormat(declared string) bool {
	return strings.HasSuffix(declared, "+zip") ||
		strings.HasPrefix(declared, "application/vnd.openxmlformats-officedocument.") ||
		strings.HasPrefix(declared, "application/vnd.oasis.opendocument.") ||
		strings.HasPrefix(declared, "application/vnd.ms-") && strings.HasSuffix(declared, ".macroenabled.12") ||
		slices.Contains(zipFormats, declared)
}

// textEncodedTypes are formats whose bytes are text, which sniffing names text/plain, but which
// text extraction leaves alone because they encode other data.
var textEncodedTypes = []string{"application/mbox", "application/postscript", "application/rtf", "message/rfc822"}

// sniffedAliases lists the other names in use for the types that sniffing names.
var sniffedAliases = map[string][]string{
	"application/ogg":              {"audio/ogg", "audio/opus", "video/ogg"},
	"application/pdf":              {"application/x-pdf"},
	"application/x-gzip":           {"application/gzip"},
	"audio/aiff":                   {"audio/x-aiff"},
	"audio/mpeg":                   {"audio/mp3", "audio/mpeg3", "audio/x-mpeg-3"},
	"audio/wave":                   {"audio/vnd.wave", "audio/wav", "audio/x-wav"},
	"image/x-icon":                 {"image/vnd.microsoft.icon"},
	"video/avi":                    {"video/x-msvideo"},
	"video/mp4":                    {"audio/m4a", "audio/mp4", "audio/x-m4a"},
	"video/webm":                   {"audio/webm"},
	"application/x-rar-compressed": {"application/vnd.rar"},
}

// zipFormats are formats built on zip archives whose names say nothing of it.
var zipFormats = []string{
	"application/java-archive",
	"application/vnd.android.package-archive",
	"application/vnd.apple.iwork",
	"application/vnd.apple.keynote",
	"application/vnd.apple.numbers",
	"application/vnd.apple.pages",
	"application/vnd.ms-xpsdocument",
	"application/x-zip-compressed",
}

// TextMediaType reports whether text extraction reads a file of the media type as text: text/*,
// JSON, XML and their suffixes, and the types in use for scripts, data and configuration that
// are plain text.
func TextMediaType(value string) bool {
	value = strings.ToLower(value)
	return strings.HasPrefix(value, "text/") || strings.HasSuffix(value, "+json") || strings.HasSuffix(value, "+xml") ||
		slices.Contains(textApplicationTypes, value)
}

// textApplicationTypes are the application types of plain text formats. Formats that hold
// binary data or other encoded parts, such as RTF, Protocol Buffers and email messages, are left
// out.
var textApplicationTypes = []string{
	"application/csv",
	"application/ecmascript",
	"application/graphql",
	"application/javascript",
	"application/json",
	"application/json5",
	"application/jsonl",
	"application/sql",
	"application/toml",
	"application/typescript",
	"application/x-awk",
	"application/x-bash",
	"application/x-diff",
	"application/x-graphql",
	"application/x-httpd-php",
	"application/x-httpd-php-source",
	"application/x-javascript",
	"application/x-json5",
	"application/x-latex",
	"application/x-ndjson",
	"application/x-patch",
	"application/x-perl",
	"application/x-php",
	"application/x-powershell",
	"application/x-ruby",
	"application/x-rust",
	"application/x-scala",
	"application/x-sh",
	"application/x-shellscript",
	"application/x-sql",
	"application/x-subrip",
	"application/x-terraform",
	"application/x-tex",
	"application/x-toml",
	"application/x-yaml",
	"application/xml",
	"application/yaml",
}
