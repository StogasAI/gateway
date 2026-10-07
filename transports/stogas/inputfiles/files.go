// Package inputfiles inspects declared attachments without fetching remote
// resources or decoding binary formats. Only opted-in UTF-8 text is expanded.
package inputfiles

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
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

// Process borrows unchanged JSON. reserveExpansion admits the worst-case JSON
// expansion before decoding text or allocating its replacement containers.
func Process(fields map[string]json.RawMessage, responses, extract bool, reserveExpansion func(int) error) (Stats, error) {
	p := processor{extract: extract, reserve: reserveExpansion}
	field := "messages"
	if responses {
		field = "input"
	}
	raw := bytes.TrimSpace(fields[field])
	if len(raw) == 0 || raw[0] != '[' {
		return p.stats, nil
	}
	items, err := rawjson.Array(raw)
	if err != nil {
		return Stats{}, err
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
			return Stats{}, err
		}
		itemChanged := false
		for j, raw := range blocks {
			block, err := rawjson.Object(raw)
			if err != nil {
				continue
			}
			replacement, err := p.block(block, responses)
			if err != nil {
				return Stats{}, err
			}
			if replacement != nil {
				blocks[j], itemChanged = replacement, true
			}
		}
		if itemChanged {
			item["content"], err = sonic.Marshal(blocks)
			if err != nil {
				return Stats{}, err
			}
			items[i], err = sonic.Marshal(item)
			if err != nil {
				return Stats{}, err
			}
			changed = true
		}
	}
	if changed {
		encoded, err := sonic.Marshal(items)
		if err != nil {
			return Stats{}, err
		}
		fields[field] = encoded
	}
	return p.stats, nil
}

type processor struct {
	stats     Stats
	extract   bool
	reserve   func(int) error
	expansion int
}

func (p *processor) block(block map[string]json.RawMessage, responses bool) (json.RawMessage, error) {
	kind := stringField(block, "type")
	var file map[string]json.RawMessage
	var data, sourceURL, id string
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
	if id != "" {
		p.stats.IDs++
		p.stats.Opaque = true
		return nil, nil
	}
	if strings.HasPrefix(sourceURL, "data:") {
		data, sourceURL = sourceURL, ""
	}
	if sourceURL != "" {
		p.stats.URLs++
		p.stats.Opaque = true
		return nil, nil
	}
	mediaType, payload, err := ParseInline(data, stringField(file, "file_type"))
	if err != nil {
		return nil, err
	}
	if document && p.extract && textMediaType(mediaType) {
		// Every UTF-8 byte may require six JSON bytes. The existing request lease
		// also covers simultaneous encoded and decoded representations.
		p.expansion += base64.StdEncoding.DecodedLen(len(payload)) * 6
		if p.reserve != nil {
			if err := p.reserve(p.expansion); err != nil {
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
		text := string(decoded)
		if raw, exists := file["filename"]; exists {
			var name string
			if err := sonic.Unmarshal(raw, &name); err != nil || strings.TrimSpace(name) == "" {
				return nil, errors.New("filename must be a non-empty string")
			}
		}
		if name := stringField(file, "filename"); name != "" {
			text = name + "\n" + text
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

func stringField(fields map[string]json.RawMessage, key string) string {
	var value string
	_ = json.Unmarshal(fields[key], &value)
	return value
}

func textMediaType(value string) bool {
	value = strings.ToLower(value)
	return strings.HasPrefix(value, "text/") || value == "application/json" || value == "application/xml" || strings.HasSuffix(value, "+json") || strings.HasSuffix(value, "+xml")
}
