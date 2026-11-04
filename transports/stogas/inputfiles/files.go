// Package inputfiles inspects declared attachments without fetching remote
// resources or decoding binary formats. Only opted-in UTF-8 text is expanded,
// and content sniffing reads no more than a payload's first 512 bytes.
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
	"strings"
	"unicode/utf8"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

type Stats struct {
	Count       int
	URLs        int
	IDs         int
	InlineBytes int
	Opaque      bool
}

// Options say what Process does with a request's attachments.
type Options struct {
	// Extract turns inline text files into prompt text.
	Extract bool
	// Native reports whether the deployment reads the text file at a path, such as
	// messages[0].content[1], as a file, which then stays one. Nil extracts every text file.
	Native func(path string) bool
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

// replaceBlocks visits the content blocks of each message and re-encodes only
// the containers whose blocks were replaced. It names each block by its path, as
// messages[0].content[1].
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
		if err != nil {
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
	kind := stringField(block, "type")
	var file map[string]json.RawMessage
	var data, sourceURL, id, audioType string
	document := false
	switch {
	case !responses && kind == "file":
		var err error
		file, err = rawjson.Object(block["file"])
		if err != nil {
			return nil, errors.New("file must be an object")
		}
		document = true
	case responses && kind == "input_file":
		file, document = block, true
	case !responses && kind == "image_url":
		image, err := rawjson.Object(block["image_url"])
		if err != nil {
			return nil, errors.New("image_url must be an object")
		}
		sourceURL, id = stringField(image, "url"), stringField(image, "file_id")
	case responses && kind == "input_image":
		sourceURL, id = stringField(block, "image_url"), stringField(block, "file_id")
	case !responses && kind == "input_audio":
		audio, err := rawjson.Object(block["input_audio"])
		if err != nil {
			return nil, errors.New("input_audio must be an object")
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
		return nil, errors.New("an attachment requires exactly one inline payload, URL, or provider file ID")
	}
	p.stats.Count++
	if strings.HasPrefix(sourceURL, "data:") {
		data, sourceURL = sourceURL, ""
	}
	mediaType, payload := audioType, ""
	if data != "" {
		var err error
		if mediaType, payload, err = ParseInline(data, stringField(file, "file_type")); err != nil {
			return nil, err
		}
		if audioType != "" {
			mediaType = audioType
		}
	}
	if p.Check != nil {
		resolved, err := ResolveMediaType(kind, mediaType, payload)
		if err != nil {
			return nil, fmt.Errorf("%s %w", path, err)
		}
		if err := p.Check(path, resolved); err != nil {
			return nil, err
		}
	}
	if id != "" {
		p.stats.IDs++
		p.stats.Opaque = true
		return nil, nil
	}
	if sourceURL != "" {
		p.stats.URLs++
		p.stats.Opaque = true
		return nil, nil
	}
	if document && p.Extract && TextMediaType(mediaType) && (p.Native == nil || !p.Native(path)) {
		// Every UTF-8 byte may require six JSON bytes. The existing request lease
		// also covers simultaneous encoded and decoded representations.
		p.expansion += base64.StdEncoding.DecodedLen(len(payload)) * 6
		if p.Reserve != nil {
			if err := p.Reserve(p.expansion); err != nil {
				return nil, err
			}
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(payload)
		if err != nil {
			return nil, errors.New("inline attachment has invalid base64")
		}
		if !utf8.Valid(decoded) || bytes.IndexByte(decoded, 0) >= 0 {
			return nil, errors.New("text extraction requires UTF-8 text without NUL bytes")
		}
		p.stats.InlineBytes += len(decoded)
		// Reject extra members rather than silently removing request semantics.
		for key := range file {
			if key != "type" && key != "file_data" && key != "filename" && key != "file_type" && key != "cache_control" && key != "prompt_cache_breakpoint" {
				return nil, errors.New("unsupported text attachment field")
			}
			if !responses && (key == "type" || key == "cache_control" || key == "prompt_cache_breakpoint") {
				return nil, errors.New("unsupported text attachment field")
			}
		}
		for key := range block {
			if !responses && key != "type" && key != "file" && key != "cache_control" && key != "prompt_cache_breakpoint" {
				return nil, errors.New("unsupported text attachment block field")
			}
		}
		if raw, exists := file["filename"]; exists {
			var name string
			if err := sonic.Unmarshal(raw, &name); err != nil || strings.TrimSpace(name) == "" {
				return nil, errors.New("filename must be a non-empty string")
			}
		}
		// The first line keeps what the file part said of the file: its name and media type.
		header := "(" + mediaType + ")"
		if name := stringField(file, "filename"); name != "" {
			header = name + " " + header
		}
		text := header + "\n" + string(decoded)
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
		replacement["text"], err = sonic.Marshal(text)
		if err != nil {
			return nil, err
		}
		return sonic.Marshal(replacement)
	}
	// A bounded decoder validates and counts binary input without retaining a
	// second decoded file. No image, archive, document, or media parser runs here.
	count, err := io.Copy(io.Discard, base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(payload)))
	if err != nil {
		return nil, errors.New("inline attachment has invalid base64")
	}
	p.stats.InlineBytes += int(count)
	p.stats.Opaque = true
	return nil, nil
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
