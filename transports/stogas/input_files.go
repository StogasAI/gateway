package stogas

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/inputfiles"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

// validateNativeAttachment enforces the gateway's wire and billing surface.
// Provider file-size, page, resolution and tokenization rules remain upstream.
func validateNativeAttachment(state *State, block map[string]json.RawMessage, path string, responses bool) error {
	if state == nil || state.Resolution == nil {
		return catalog.ErrUnsupportedRequest
	}
	kind := rawString(block["type"])
	file := block
	modality := ""
	switch kind {
	case "image_url":
		if err := rejectUnsupportedInputKeys(block, path, "type", "image_url", "cache_control", "prompt_cache_breakpoint"); err != nil {
			return err
		}
		var err error
		file, err = rawjson.Object(block["image_url"])
		if err != nil {
			return invalidRequest(path + ".image_url must be an object")
		}
		if err := rejectUnsupportedInputKeys(file, path+".image_url", "url", "detail"); err != nil {
			return err
		}
		modality = "image"
	case "input_image":
		if err := rejectUnsupportedInputKeys(block, path, "type", "image_url", "file_id", "detail", "cache_control", "prompt_cache_breakpoint"); err != nil {
			return err
		}
		modality = "image"
	case "input_audio":
		if responses || responsesUsesAnthropicWire(state) {
			return invalidRequest(path + " audio is not supported by this route")
		}
		if err := rejectUnsupportedInputKeys(block, path, "type", "input_audio"); err != nil {
			return err
		}
		var err error
		file, err = rawjson.Object(block["input_audio"])
		if err != nil {
			return invalidRequest(path + ".input_audio must be an object")
		}
		if err := rejectUnsupportedInputKeys(file, path+".input_audio", "data", "format"); err != nil {
			return err
		}
		modality = "audio"
	case "file", "input_file":
		if !responses {
			if err := rejectUnsupportedInputKeys(block, path, "type", "file", "cache_control", "prompt_cache_breakpoint"); err != nil {
				return err
			}
			var err error
			file, err = rawjson.Object(block["file"])
			if err != nil {
				return invalidRequest(path + ".file must be an object")
			}
		}
		allowed := []string{"file_data", "file_url", "file_id", "filename", "file_type"}
		if responses {
			allowed = append(allowed, "type", "cache_control", "prompt_cache_breakpoint")
		}
		if err := rejectUnsupportedInputKeys(file, path, allowed...); err != nil {
			return err
		}

	default:
		return invalidRequest(path + " attachment type is not supported")
	}
	// Decode attachment strings once. Large base64 fields must not be decoded
	// again merely to validate their type or test whether they are empty.
	values := make(map[string]string)
	for _, key := range []string{"url", "image_url", "file_url", "file_data", "file_id", "filename", "file_type", "detail", "data", "format"} {
		if value, exists := file[key]; exists {
			text, ok := rawStringValue(value)
			if !ok || !hasNonWhitespace(text) {
				return invalidRequest(path + "." + key + " must be a non-empty string")
			}
			values[key] = text
		}
	}
	var sourceURL, data, id string
	switch kind {
	case "image_url":
		sourceURL = values["url"]
	case "input_image":
		sourceURL, id = values["image_url"], values["file_id"]
	case "input_audio":
		data = values["data"]
	case "file", "input_file":
		sourceURL, data, id = values["file_url"], values["file_data"], values["file_id"]
	}
	if kind == "input_image" && id != "" && responsesUsesAnthropicWire(state) {
		return invalidRequest(path + " image file IDs are not supported by this route")
	}
	if kind == "file" || kind == "input_file" {
		if sourceURL != "" && !responses && !responsesUsesAnthropicWire(state) {
			return invalidRequest(path + " file URLs require Responses or an Anthropic-format deployment")
		}
		if rawJSONValueSet(file["file_type"]) && !responsesUsesAnthropicWire(state) {
			return invalidRequest(path + " native files must declare MIME type in a base64 data URL, not file_type")
		}
		formats := state.Resolution.Deployment.FileInputs
		if len(formats.MediaTypes) == 0 {
			return invalidRequest(path + " native files are not supported by this deployment")
		}
		if data != "" {
			extension := strings.ToLower(filepath.Ext(values["filename"]))
			mediaType, _, err := inputfiles.ParseInline(data, values["file_type"])
			if err != nil {
				return invalidRequest(path + " has an invalid declared file type")
			}
			if mediaType != "" && mediaType != "application/octet-stream" {
				if !slices.Contains(formats.MediaTypes, mediaType) {
					return invalidRequest(path + " native file media type is not supported by this deployment")
				}
			} else if !slices.Contains(formats.Extensions, extension) {
				return invalidRequest(path + " requires a supported file media type or filename extension")
			}
			if responsesUsesAnthropicWire(state) {
				// Core treats untyped raw base64 as PDF, and raw file_type text/plain
				// as literal text. A data URL keeps native text bytes unambiguous.
				if mediaType == "application/octet-stream" || (!strings.HasPrefix(data, "data:") && mediaType != "application/pdf" && !(mediaType == "" && extension == ".pdf")) {
					return invalidRequest(path + " native text files require a typed base64 data URL")
				}
			}
		}
		if strings.HasPrefix(sourceURL, "data:") {
			return invalidRequest(path + " inline files must use file_data")
		}
	}
	if modality != "" && !slices.Contains(state.Resolution.Deployment.Capabilities.InputModalities, modality) {
		return invalidRequest(path + " input modality is not supported by this deployment")
	}
	if id != "" && !state.PreparedCredential.UsesBYOK() {
		return invalidRequest("Provider file IDs require BYOK")
	}
	if sourceURL != "" && !strings.HasPrefix(sourceURL, "data:") {
		parsed, err := url.Parse(sourceURL)
		if err != nil || parsed.Hostname() == "" || parsed.Scheme != "https" && parsed.Scheme != "http" {
			return invalidRequest(path + " requires an HTTP(S) URL or base64 data URL")
		}
	}

	if sourceURL == "" && data == "" && id == "" {
		return invalidRequest(path + " requires attachment content")
	}
	return nil
}
