// Package inputfiles inspects declared attachments without fetching remote
// resources. Only opted-in files are expanded: UTF-8 text, and the XML of Office
// files. Content sniffing reads no more than a payload's first 512 bytes.
package inputfiles

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

type Stats struct {
	Count       int
	URLs        int
	IDs         int
	InlineBytes int
	// Opaque names the first attachment whose content the gateway does not read, or is "" when
	// there is none: a URL, a file ID, or a file that stays one, unless it is a text file, which
	// Text reads. An Office file that stays a file is opaque.
	Opaque string
	// Extracted counts the files that became prompt text, and ExtractionTime is what reading
	// them took.
	Extracted      int
	ExtractionTime time.Duration
}

// PartError refuses the attachment at Path, such as messages[0].content[1].
type PartError struct {
	Path   string
	Reason string
}

func (e *PartError) Error() string { return e.Path + " " + e.Reason }

// Options say what Process does with a request's attachments.
type Options struct {
	// Extract names the families of inline files that become prompt text.
	Extract Families
	// File reports whether the text or Office file at a path, such as messages[0].content[1],
	// stays a file, because the deployment reads it and nothing requires its text, and the media
	// type that a text file must declare for the deployment, or "" for its own. Nil keeps no
	// such file.
	File func(path string) (mediaType string, ok bool)
	// Text receives the text of each text file that stays a file, which the provider reads as
	// prompt text, so that the caller can count it.
	Text func(text string)
	// Check refuses an attachment at a path by its media type. Nil checks nothing, and leaves
	// the content unsniffed.
	Check func(path string, mediaType MediaType) error
	// Reserve admits the worst-case JSON expansion before decoding text or allocating its
	// replacement containers.
	Reserve func(int) error
}

// Process borrows unchanged JSON.
func Process(fields map[string]json.RawMessage, responses bool, options Options) (Stats, error) {
	p := processor{Options: options}
	if err := replaceBlocks(fields, responses, func(path string, block map[string]json.RawMessage) (json.RawMessage, error) {
		return p.block(path, block, responses)
	}); err != nil {
		return Stats{}, err
	}
	return p.stats, nil
}

// Describe returns a copy of a validated request whose inline attachments are
// replaced by their declared media type and the size and SHA-256 of their
// decoded bytes. URLs, provider file IDs and other values are borrowed.
func Describe(fields map[string]json.RawMessage, responses bool) (map[string]json.RawMessage, error) {
	described := maps.Clone(fields)
	err := replaceBlocks(described, responses, func(_ string, block map[string]json.RawMessage) (json.RawMessage, error) {
		parent, key := "", ""
		switch kind := stringField(block, "type"); {
		case !responses && kind == "image_url":
			parent, key = "image_url", "url"
		case !responses && kind == "input_audio":
			parent, key = "input_audio", "data"
		case !responses && kind == "file":
			parent, key = "file", "file_data"
		case responses && kind == "input_image":
			key = "image_url"
		case responses && kind == "input_file":
			key = "file_data"
		default:
			return nil, nil
		}
		holder := block
		if parent != "" {
			var err error
			if holder, err = rawjson.Object(block[parent]); err != nil {
				return nil, err
			}
		}
		data := stringField(holder, key)
		inline := key == "data" || key == "file_data" || strings.HasPrefix(data, "data:")
		if data == "" || !inline {
			return nil, nil
		}
		mediaType, payload, err := ParseInline(data, stringField(holder, "file_type"))
		if err != nil {
			return nil, err
		}
		digest := sha256.New()
		size, err := io.Copy(digest, base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(payload)))
		if err != nil {
			return nil, errors.New("inline attachment has invalid base64")
		}
		holder[key], err = sonic.Marshal(struct {
			MediaType string `json:"media_type,omitempty"`
			Size      int64  `json:"size"`
			SHA256    string `json:"sha256"`
		}{mediaType, size, hex.EncodeToString(digest.Sum(nil))})
		if err != nil {
			return nil, err
		}
		if parent != "" {
			if block[parent], err = sonic.Marshal(holder); err != nil {
				return nil, err
			}
		}
		return sonic.Marshal(block)
	})
	if err != nil {
		return nil, err
	}
	return described, nil
}

// replaceBlocks visits the content blocks of each user message and re-encodes
// only the containers whose blocks were replaced. It names each block by its
// path, as messages[0].content[1]. Other messages stay as sent: routing reads
// attachments only from user messages, and the request checks refuse an
// attachment anywhere else.
func replaceBlocks(fields map[string]json.RawMessage, responses bool, replace func(string, map[string]json.RawMessage) (json.RawMessage, error)) error {
	field := "messages"
	if responses {
		field = "input"
	}
	raw := bytes.TrimSpace(fields[field])
	if len(raw) == 0 || raw[0] != '[' {
		return nil
	}
	items, err := rawjson.Array(raw)
	if err != nil {
		return err
	}
	changed := false
	for i, itemRaw := range items {
		item, err := rawjson.Object(itemRaw)
		if err != nil || stringField(item, "role") != "user" {
			continue
		}
		// Tool results and reasoning replay are separate protocol values.
		if responses && stringField(item, "type") != "" && stringField(item, "type") != "message" {
			continue
		}
		content := bytes.TrimSpace(item["content"])
		if len(content) == 0 || content[0] != '[' {
			continue
		}
		blocks, err := rawjson.Array(content)
		if err != nil {
			return err
		}
		itemChanged := false
		for j, raw := range blocks {
			block, err := rawjson.Object(raw)
			if err != nil {
				continue
			}
			replacement, err := replace(fmt.Sprintf("%s[%d].content[%d]", field, i, j), block)
			if err != nil {
				return err
			}
			if replacement != nil {
				blocks[j], itemChanged = replacement, true
			}
		}
		if itemChanged {
			if item["content"], err = sonic.Marshal(blocks); err != nil {
				return err
			}
			if items[i], err = sonic.Marshal(item); err != nil {
				return err
			}
			changed = true
		}
	}
	if changed {
		encoded, err := sonic.Marshal(items)
		if err != nil {
			return err
		}
		fields[field] = encoded
	}
	return nil
}

type processor struct {
	Options
	stats     Stats
	expansion int
}

func (p *processor) block(path string, block map[string]json.RawMessage, responses bool) (json.RawMessage, error) {
	refuse := func(reason string) error { return &PartError{Path: path, Reason: reason} }
	kind := stringField(block, "type")
	var file map[string]json.RawMessage
	var data, sourceURL, id, audioType string
	document := false
	switch {
	case !responses && kind == "file":
		var err error
		file, err = rawjson.Object(block["file"])
		if err != nil {
			return nil, refuse("file must be an object")
		}
		document = true
	case responses && kind == "input_file":
		file, document = block, true
	case !responses && kind == "image_url":
		image, err := rawjson.Object(block["image_url"])
		if err != nil {
			return nil, refuse("image_url must be an object")
		}
		sourceURL, id = stringField(image, "url"), stringField(image, "file_id")
	case responses && kind == "input_image":
		sourceURL, id = stringField(block, "image_url"), stringField(block, "file_id")
	case !responses && kind == "input_audio":
		audio, err := rawjson.Object(block["input_audio"])
		if err != nil {
			return nil, refuse("input_audio must be an object")
		}
		data = stringField(audio, "data")
		audioType = AudioMediaType(stringField(audio, "format"))
	default:
		return nil, nil
	}
	if document {
		data, sourceURL, id = stringField(file, "file_data"), stringField(file, "file_url"), stringField(file, "file_id")
	}
	sources := 0
	for _, value := range []string{data, sourceURL, id} {
		if value != "" {
			sources++
		}
	}
	if sources != 1 {
		return nil, refuse("requires exactly one inline payload, URL or provider file ID")
	}
	p.stats.Count++
	if strings.HasPrefix(sourceURL, "data:") {
		data, sourceURL = sourceURL, ""
	}
	mediaType, payload := audioType, ""
	if data != "" {
		var err error
		if mediaType, payload, err = ParseInline(data, stringField(file, "file_type")); err != nil {
			return nil, refuse(err.Error())
		}
		if audioType != "" {
			mediaType = audioType
		}
	}
	if p.Check != nil {
		resolved, err := ResolveMediaType(kind, mediaType, payload)
		if err != nil {
			return nil, refuse(err.Error())
		}
		if err := p.Check(path, resolved); err != nil {
			return nil, err
		}
	}
	if id != "" {
		p.stats.IDs++
		p.opaque(path)
		return nil, nil
	}
	if sourceURL != "" {
		p.stats.URLs++
		p.opaque(path)
		return nil, nil
	}
	if family := Family(""); document && data != "" {
		family = FileFamily(mediaType, payload, stringField(file, "filename"))
		fileType, kept := "", false
		if family != "" && p.File != nil {
			fileType, kept = p.File(path)
		}
		switch {
		case family == FamilyText && (kept || p.Extract.Text):
			replacement, text, err := p.text(path, block, file, responses, mediaType, payload, fileType, kept)
			if text || err != nil {
				return replacement, err
			}
		case family == FamilyOffice && !kept && p.Extract.Office:
			return p.office(path, block, file, responses, mediaType, payload)
		}
	}
	// A bounded decoder validates and counts binary input without retaining a
	// second decoded file. No image or media parser runs here.
	count, err := io.Copy(io.Discard, base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(payload)))
	if err != nil {
		return nil, refuse("has invalid base64")
	}
	p.stats.InlineBytes += int(count)
	p.opaque(path)
	return nil, nil
}

// text reads the inline text file of a block. A kept file stays a file: its text goes to Text,
// and it declares fileType where that is not "". Any other file becomes a text block, except
// one that names no text type and is not UTF-8 text, which stays an opaque file: text then
// reports false.
func (p *processor) text(path string, block, file map[string]json.RawMessage, responses bool, mediaType, payload, fileType string, kept bool) (json.RawMessage, bool, error) {
	refuse := func(reason string) (json.RawMessage, bool, error) {
		return nil, false, &PartError{Path: path, Reason: reason}
	}
	started := time.Now()
	// The request lease covers the decoded text beside the encoded file, and what replaces the
	// file: a data URL of the same payload, or text, where every UTF-8 byte may require six
	// JSON bytes.
	size := base64.StdEncoding.DecodedLen(len(payload))
	switch {
	case !kept:
		size *= 6
	case fileType != "":
		size += len(payload) + len(fileType) + len("data:;base64,")
	}
	p.expansion += size
	if p.Reserve != nil {
		if err := p.Reserve(p.expansion); err != nil {
			return nil, false, err
		}
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(payload)
	if err != nil {
		return refuse("has invalid base64")
	}
	valid := utf8.Valid(decoded) && bytes.IndexByte(decoded, 0) < 0
	if !valid && !kept {
		if TextMediaType(mediaType) {
			return refuse("is not UTF-8 text without NUL bytes, which text extraction requires")
		}
		return nil, false, nil
	}
	p.stats.InlineBytes += len(decoded)
	if kept {
		// The provider decides whether it reads text in another encoding, which the gateway
		// cannot count.
		if !valid {
			p.opaque(path)
		} else if p.Text != nil {
			p.Text(string(decoded))
		}
		if fileType == "" {
			return nil, true, nil
		}
		delete(file, "file_type")
		if file["file_data"], err = sonic.Marshal("data:" + fileType + ";base64," + payload); err != nil {
			return nil, false, err
		}
		replacement := file
		if !responses {
			if block["file"], err = sonic.Marshal(file); err != nil {
				return nil, false, err
			}
			replacement = block
		}
		encoded, err := sonic.Marshal(replacement)
		return encoded, true, err
	}
	// Only a text type says more of the file than its name.
	if !TextMediaType(mediaType) {
		mediaType = ""
	}
	replacement, err := textBlock(path, block, file, responses, mediaType, string(decoded))
	p.extracted(started)
	return replacement, true, err
}

// extracted records a file that became prompt text.
func (p *processor) extracted(started time.Time) {
	p.stats.Extracted++
	p.stats.ExtractionTime += time.Since(started)
}

// office reads the inline Office file of a block and returns the text block that replaces it.
func (p *processor) office(path string, block, file map[string]json.RawMessage, responses bool, mediaType, payload string) (json.RawMessage, error) {
	refuse := func(reason string) (json.RawMessage, error) { return nil, &PartError{Path: path, Reason: reason} }
	started := time.Now()
	// The request lease covers the decoded archive, and then what the extraction keeps.
	retain := func(bytes int) error {
		p.expansion += bytes
		if p.Reserve != nil {
			return p.Reserve(p.expansion)
		}
		return nil
	}
	if err := retain(base64.StdEncoding.DecodedLen(len(payload))); err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(payload)
	if err != nil {
		return refuse("has invalid base64")
	}
	text, err := extractOffice(decoded, officeFile(mediaType, payload, stringField(file, "filename")), retain)
	var capacity capacityError
	var reason officeError
	switch {
	case errors.As(err, &capacity):
		return nil, capacity.error
	case errors.As(err, &reason):
		return refuse(string(reason))
	case err != nil:
		return nil, err
	}
	p.stats.InlineBytes += len(decoded)
	// Only a type that names the Office format says more than the filename.
	if officeMediaTypes[strings.ToLower(mediaType)] == 0 {
		mediaType = ""
	}
	replacement, err := textBlock(path, block, file, responses, mediaType, text)
	p.extracted(started)
	return replacement, err
}

// textBlock builds the text block that replaces a file part: the file's text below a first line
// that keeps what the part said of the file, its name and its media type. mediaType is "" for a
// type that says nothing of the format.
func textBlock(path string, block, file map[string]json.RawMessage, responses bool, mediaType, text string) (json.RawMessage, error) {
	refuse := func(reason string) (json.RawMessage, error) { return nil, &PartError{Path: path, Reason: reason} }
	// Reject extra members rather than silently removing request semantics. Sorted keys name
	// the same member each time.
	for _, key := range slices.Sorted(maps.Keys(file)) {
		if key != "type" && key != "file_data" && key != "filename" && key != "file_type" && key != "cache_control" && key != "prompt_cache_breakpoint" ||
			!responses && (key == "type" || key == "cache_control" || key == "prompt_cache_breakpoint") {
			return refuse("has " + key + ", which text extraction cannot keep")
		}
	}
	for _, key := range slices.Sorted(maps.Keys(block)) {
		if !responses && key != "type" && key != "file" && key != "cache_control" && key != "prompt_cache_breakpoint" {
			return refuse("has " + key + ", which text extraction cannot keep")
		}
	}
	if raw, exists := file["filename"]; exists {
		var name string
		if err := sonic.Unmarshal(raw, &name); err != nil || strings.TrimSpace(name) == "" {
			return refuse("filename must be a non-empty string")
		}
	}
	header := ""
	if mediaType != "" {
		header = "(" + mediaType + ")"
	}
	if name := stringField(file, "filename"); name != "" {
		header = strings.TrimSpace(name + " " + header)
	}
	if header != "" {
		text = header + "\n" + text
	}
	replacement := map[string]json.RawMessage{}
	for _, key := range []string{"cache_control", "prompt_cache_breakpoint"} {
		if raw, ok := block[key]; ok {
			replacement[key] = raw
		}
	}
	replacement["type"] = json.RawMessage(`"text"`)
	if responses {
		replacement["type"] = json.RawMessage(`"input_text"`)
	}
	var err error
	if replacement["text"], err = sonic.Marshal(text); err != nil {
		return nil, err
	}
	return sonic.Marshal(replacement)
}

func (p *processor) opaque(path string) {
	if p.stats.Opaque == "" {
		p.stats.Opaque = path
	}
}

// ParseInline borrows the base64 payload and normalizes its declared media
// type. It does not decode content or infer a format from a filename.
func ParseInline(data, declared string) (string, string, error) {
	mediaType := ""
	if declared != "" {
		var err error
		mediaType, _, err = mime.ParseMediaType(declared)
		if err != nil {
			return "", "", errors.New("file_type has an invalid media type")
		}
	}
	if !strings.HasPrefix(data, "data:") {
		return mediaType, data, nil
	}
	header, payload, ok := strings.Cut(data[5:], ",")
	if !ok || !strings.HasSuffix(header, ";base64") {
		return "", "", errors.New("inline data URLs must use base64")
	}
	parsed, _, err := mime.ParseMediaType(strings.TrimSuffix(header, ";base64"))
	if err != nil {
		return "", "", errors.New("inline data URL has an invalid media type")
	}
	if mediaType != "" && mediaType != parsed {
		return "", "", errors.New("file_type conflicts with the inline data URL")
	}
	return parsed, payload, nil
}

// Sonic reads a multi-megabyte base64 string about three times faster than
// encoding/json. Values were already validated when they were borrowed.
func stringField(fields map[string]json.RawMessage, key string) string {
	var value string
	_ = sonic.Unmarshal(fields[key], &value)
	return value
}

// AudioMediaType names the media type of a Chat audio part's format, such as wav.
func AudioMediaType(format string) string {
	switch format = strings.ToLower(format); format {
	case "":
		return ""
	case "mp3":
		return "audio/mpeg"
	}
	return "audio/" + format
}
