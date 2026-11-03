package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/inputfiles"
	"github.com/maximhq/bifrost/transports/stogas/policy"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

// DocumentFormats lists the file types a route's provider reads natively from a document
// part. Image and audio parts follow the deployment's input modalities; request-time text
// extraction runs first.
type DocumentFormats struct {
	MediaTypes []string `json:"mediaTypes"`
	Extensions []string `json:"extensions"`
}

// The policy vocabulary pass checks the form of each entry.
func validateDocumentFormats(value DocumentFormats) error {
	for _, values := range [][]string{value.MediaTypes, value.Extensions} {
		if values == nil {
			return errors.New("document formats must be explicit arrays")
		}
		for i := 1; i < len(values); i++ {
			if values[i-1] >= values[i] {
				return errors.New("document formats must be sorted and unique")
			}
		}
	}
	if len(value.MediaTypes) == 0 && len(value.Extensions) != 0 {
		return errors.New("file extensions require document media types")
	}
	return nil
}

// Attachment is an image, audio or document part of a user message, with what a deployment
// needs to read it.
type Attachment struct {
	// Path names the part in errors, such as messages[0].content[1].
	Path string
	// Kind is the part's type: image_url, input_image, input_audio, file or input_file.
	Kind      string
	Responses bool
	// URL, Data and ID are the part's sources: a URL, data URLs included, an inline payload and
	// a provider file ID. The checks read no more of a source than a data URL's header.
	URL, Data, ID string
	Filename      string
	FileType      string
	// text marks an inline text file, which text extraction turns into prompt text.
	text bool
}

// AttachmentError reports why a deployment cannot read an attachment, or nil when it can.
// Routing skips the deployments that cannot read a request's attachments, and the checks of
// the selected deployment call it again, so the two agree.
func AttachmentError(provider schemas.ModelProvider, deployment Deployment, attachment Attachment) error {
	claude := UsesClaudeWire(provider, deployment.ModelID)
	modality := ""
	switch attachment.Kind {
	case "image_url", "input_image":
		modality = "image"
		if attachment.Kind == "input_image" && attachment.ID != "" && claude {
			return attachmentRefusal(attachment.Path + " image file IDs are not supported by this route")
		}
	case "input_audio":
		modality = "audio"
	case "file", "input_file":
		if err := documentError(claude, deployment.DocumentFormats, attachment); err != nil {
			return err
		}
	}
	if modality != "" && !slices.Contains(deployment.InputModalities, modality) {
		return attachmentRefusal(attachment.Path + " " + modality + " input is not supported by the selected deployment")
	}
	// Claude that AWS or Google runs has no Files API and fetches no URL.
	if CloudRunsClaude(provider, deployment) {
		if attachment.ID != "" {
			return attachmentRefusal(attachment.Path + " file IDs are not supported when AWS or Google runs Claude")
		}
		if attachment.URL != "" && !strings.HasPrefix(attachment.URL, "data:") {
			return attachmentRefusal(attachment.Path + " URL sources are not supported when AWS or Google runs Claude; send the content inline")
		}
	}
	return nil
}

func documentError(claude bool, formats DocumentFormats, attachment Attachment) error {
	path := attachment.Path
	if attachment.URL != "" && !attachment.Responses && !claude {
		return attachmentRefusal(path + " file URLs require Responses or an Anthropic-format deployment")
	}
	if attachment.FileType != "" && !claude {
		return attachmentRefusal(path + " native files must declare MIME type in a base64 data URL, not file_type")
	}
	if len(formats.MediaTypes) == 0 {
		return attachmentRefusal(path + " native files are not supported by this deployment")
	}
	if attachment.Data == "" {
		return nil
	}
	extension := strings.ToLower(filepath.Ext(attachment.Filename))
	mediaType, _, err := inputfiles.ParseInline(attachment.Data, attachment.FileType)
	if err != nil {
		return attachmentRefusal(path + " has an invalid declared file type")
	}
	if mediaType != "" && mediaType != "application/octet-stream" {
		if !slices.Contains(formats.MediaTypes, mediaType) {
			return attachmentRefusal(path + " native file media type is not supported by this deployment")
		}
	} else if !slices.Contains(formats.Extensions, extension) {
		return attachmentRefusal(path + " requires a supported file media type or filename extension")
	}
	// Core treats untyped raw base64 as PDF, and raw file_type text/plain as literal text. A data
	// URL keeps native text bytes unambiguous.
	if claude && (mediaType == "application/octet-stream" || (!strings.HasPrefix(attachment.Data, "data:") && mediaType != "application/pdf" && !(mediaType == "" && extension == ".pdf"))) {
		return attachmentRefusal(path + " native text files require a typed base64 data URL")
	}
	return nil
}

func attachmentRefusal(message string) error {
	return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: message}
}

// CloudRunsClaude reports whether AWS or Google runs a Claude deployment itself, rather than
// Anthropic behind the cloud's sign-in.
func CloudRunsClaude(provider schemas.ModelProvider, deployment Deployment) bool {
	return (provider == ProviderAWS || provider == ProviderGoogleCloud) && deployment.Upstream.Hosting != "anthropic"
}

// attachmentsError reports the first attachment that a pair cannot read. A pair whose policy
// turns text files into prompt text reads each inline text file. Text extraction is never
// encrypted, so routing knows it before any plugin is opened.
func attachmentsError(attachments []Attachment, selection routingSelection, config *policy.Config) error {
	if len(attachments) == 0 {
		return nil
	}
	extracts := config.TextExtractionEnabled()
	for _, attachment := range attachments {
		if attachment.text && extracts {
			continue
		}
		if err := AttachmentError(selection.provider, selection.deployment, attachment); err != nil {
			return err
		}
	}
	return nil
}

// requestAttachments lists the attachments of the request's user messages, so that routing can
// skip the candidates that cannot read them. Where every candidate reads attachments alike, it
// returns nil and reads no message, as the candidates then fail or pass together. A part that
// fails its checks on any deployment, such as one with two sources, is left to those checks.
func requestAttachments(raw map[string]json.RawMessage, route Route, selections []routingSelection) []Attachment {
	if attachmentSupportUniform(selections) {
		return nil
	}
	field, responses := "messages", route == RouteResponses
	if responses {
		field = "input"
	}
	value := bytes.TrimSpace(raw[field])
	if len(value) == 0 || value[0] != '[' || !attachmentNamed(value) {
		return nil
	}
	items, err := rawjson.Array(value)
	if err != nil {
		return nil
	}
	var attachments []Attachment
	for i, itemRaw := range items {
		item, err := rawjson.Object(itemRaw)
		if err != nil || rawStringValue(item["role"]) != "user" {
			continue
		}
		if kind := rawStringValue(item["type"]); responses && kind != "" && kind != "message" {
			continue
		}
		content := bytes.TrimSpace(item["content"])
		if len(content) == 0 || content[0] != '[' {
			continue
		}
		blocks, err := rawjson.Array(content)
		if err != nil {
			continue
		}
		for j, blockRaw := range blocks {
			block, err := rawjson.Object(blockRaw)
			if err != nil {
				continue
			}
			if attachment, ok := readAttachment(block, fmt.Sprintf("%s[%d].content[%d]", field, i, j), responses); ok {
				attachments = append(attachments, attachment)
			}
		}
	}
	return attachments
}

// attachmentNamed reports whether messages name an attachment's type or member, so that a
// request with text only reads no message. A name spelled with escapes misses, and its
// deployment's checks still run.
func attachmentNamed(messages []byte) bool {
	for _, name := range []string{`"image_url"`, `"input_image"`, `"input_audio"`, `"file"`, `"input_file"`} {
		if bytes.Contains(messages, []byte(name)) {
			return true
		}
	}
	return false
}

// attachmentSupportUniform reports whether every candidate reads attachments alike.
func attachmentSupportUniform(selections []routingSelection) bool {
	for _, selection := range selections[min(1, len(selections)):] {
		first, other := selections[0].deployment, selection.deployment
		if slices.Contains(first.InputModalities, "image") != slices.Contains(other.InputModalities, "image") ||
			slices.Contains(first.InputModalities, "audio") != slices.Contains(other.InputModalities, "audio") ||
			!slices.Equal(first.DocumentFormats.MediaTypes, other.DocumentFormats.MediaTypes) ||
			!slices.Equal(first.DocumentFormats.Extensions, other.DocumentFormats.Extensions) ||
			UsesClaudeWire(selections[0].provider, first.ModelID) != UsesClaudeWire(selection.provider, other.ModelID) ||
			CloudRunsClaude(selections[0].provider, first) != CloudRunsClaude(selection.provider, other) {
			return false
		}
	}
	return true
}

// readAttachment reads a content part as its checks do. It reports false for a part that is not
// an attachment, or that the request's preparation refuses on any deployment.
func readAttachment(block map[string]json.RawMessage, path string, responses bool) (Attachment, bool) {
	attachment := Attachment{Path: path, Kind: rawStringValue(block["type"]), Responses: responses}
	holderKey, urlKey, dataKey, idKey := "", "", "", ""
	document := false
	switch {
	case !responses && attachment.Kind == "image_url":
		holderKey, urlKey = "image_url", "url"
	case responses && attachment.Kind == "input_image":
		urlKey, idKey = "image_url", "file_id"
	case !responses && attachment.Kind == "input_audio":
		holderKey, dataKey = "input_audio", "data"
	case !responses && attachment.Kind == "file":
		holderKey, document = "file", true
	case responses && attachment.Kind == "input_file":
		document = true
	default:
		return Attachment{}, false
	}
	if document {
		urlKey, dataKey, idKey = "file_url", "file_data", "file_id"
	}
	holder := block
	if holderKey != "" {
		var err error
		if holder, err = rawjson.Object(block[holderKey]); err != nil {
			return Attachment{}, false
		}
	}
	valid := true
	read := func(key string, head bool) string {
		if key == "" || !valid {
			return ""
		}
		value, ok := attachmentString(holder[key], head)
		valid = ok
		return value
	}
	attachment.URL, attachment.Data, attachment.ID = read(urlKey, true), read(dataKey, true), read(idKey, false)
	if document {
		attachment.Filename, attachment.FileType = read("filename", false), read("file_type", false)
	}
	sources := 0
	for _, source := range []string{attachment.URL, attachment.Data, attachment.ID} {
		if source != "" {
			sources++
		}
	}
	if !valid || sources != 1 {
		return Attachment{}, false
	}
	inline := attachment.Data
	if strings.HasPrefix(attachment.URL, "data:") {
		inline = attachment.URL
	}
	if inline != "" {
		mediaType, _, err := inputfiles.ParseInline(inline, attachment.FileType)
		if err != nil {
			return Attachment{}, false
		}
		attachment.text = document && inputfiles.TextMediaType(mediaType)
	}
	return attachment, true
}

// attachmentHeadBytes is how much of a long inline source routing decodes: a data URL's header,
// not the file.
const attachmentHeadBytes = 1024

// attachmentString reads a member that the checks take only as a string with text, as "" where
// it is absent or null. head decodes a long value only through its first comma, which ends a
// data URL's header, or its first attachmentHeadBytes bytes.
func attachmentString(raw json.RawMessage, head bool) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", true
	}
	if head && len(raw) > attachmentHeadBytes && raw[0] == '"' {
		prefix := raw[:attachmentHeadBytes]
		if comma := bytes.IndexByte(prefix, ','); comma >= 0 {
			raw = append(slices.Clip(raw[:comma+1]), '"')
		} else if bytes.IndexByte(prefix, '\\') < 0 {
			raw = append(slices.Clip(prefix), '"')
		}
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}
