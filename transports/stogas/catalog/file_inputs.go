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
	"unicode/utf8"

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
	// mediaType is what the part and the start of its content say of its type, for the
	// policy's input.mediaTypes, and mediaTypeErr why the two disagree.
	mediaType    inputfiles.MediaType
	mediaTypeErr error
}

// AttachmentError reports why the selected deployment cannot read an attachment, or nil when it
// can. Routing skips the deployments that cannot read a request's attachments with the same
// checks, so the two agree.
func AttachmentError(provider schemas.ModelProvider, deployment Deployment, attachment Attachment) error {
	return attachmentError(provider, deployment, attachment, "the selected deployment")
}

// routingSubject names the deployments of a refusal that routing gives, when no candidate is left.
const routingSubject = "any deployment that this request can use"

// attachmentError names the deployments that cannot read the attachment as subject.
func attachmentError(provider schemas.ModelProvider, deployment Deployment, attachment Attachment, subject string) error {
	claude := UsesClaudeWire(provider, deployment.ModelID)
	modality := ""
	switch attachment.Kind {
	case "image_url", "input_image":
		modality = "image"
		if attachment.Kind == "input_image" && attachment.ID != "" && claude {
			return attachmentRefusal(attachment.Path, " image file IDs are not supported by "+subject)
		}
	case "input_audio":
		modality = "audio"
	case "file", "input_file":
		if err := documentError(claude, deployment.DocumentFormats, attachment, subject); err != nil {
			return err
		}
	}
	if modality != "" && !slices.Contains(deployment.InputModalities, modality) {
		return attachmentRefusal(attachment.Path, " "+modality+" input is not supported by "+subject)
	}
	// Claude that AWS or Google runs has no Files API and fetches no URL.
	if CloudRunsClaude(provider, deployment) {
		if attachment.ID != "" {
			return attachmentRefusal(attachment.Path, " file IDs are not supported when AWS or Google runs Claude")
		}
		if attachment.URL != "" && !strings.HasPrefix(attachment.URL, "data:") {
			return attachmentRefusal(attachment.Path, " URL sources are not supported when AWS or Google runs Claude; send the content inline")
		}
	}
	return nil
}

func documentError(claude bool, formats DocumentFormats, attachment Attachment, subject string) error {
	path := attachment.Path
	if attachment.URL != "" && !attachment.Responses && !claude {
		return attachmentRefusal(path, " file URLs require Responses or an Anthropic-format deployment")
	}
	if attachment.FileType != "" && !claude {
		return attachmentRefusal(path, " native files must declare MIME type in a base64 data URL, not file_type")
	}
	if len(formats.MediaTypes) == 0 {
		return attachmentRefusal(path, " native files are not supported by "+subject)
	}
	if attachment.Data == "" {
		return nil
	}
	extension := strings.ToLower(filepath.Ext(attachment.Filename))
	mediaType, _, err := inputfiles.ParseInline(attachment.Data, attachment.FileType)
	if err != nil {
		return attachmentRefusal(path, " has an invalid declared file type")
	}
	if mediaType != "" && mediaType != "application/octet-stream" {
		if !slices.Contains(formats.MediaTypes, mediaType) {
			return attachmentRefusal(path, " native file media type is not supported by "+subject)
		}
	} else if !slices.Contains(formats.Extensions, extension) {
		return attachmentRefusal(path, " requires a supported file media type or filename extension")
	}
	// Core treats untyped raw base64 as PDF, and raw file_type text/plain as literal text. A data
	// URL keeps native text bytes unambiguous.
	if claude && (mediaType == "application/octet-stream" || (!strings.HasPrefix(attachment.Data, "data:") && mediaType != "application/pdf" && !(mediaType == "" && extension == ".pdf"))) {
		return attachmentRefusal(path, " native text files require a typed base64 data URL")
	}
	return nil
}

// AttachmentUnsupported is the code of a request whose attachment no candidate deployment reads.
const AttachmentUnsupported = "attachment_unsupported"

// attachmentRefusal refuses the attachment at path for reason, which follows the path.
func attachmentRefusal(path, reason string) error {
	return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: path + reason, Param: path}
}

// CloudRunsClaude reports whether AWS or Google runs a Claude deployment itself, rather than
// Anthropic behind the cloud's sign-in.
func CloudRunsClaude(provider schemas.ModelProvider, deployment Deployment) bool {
	return (provider == ProviderAWS || provider == ProviderGoogleCloud) && deployment.Upstream.Hosting != "anthropic"
}

// mediaTypeRefusal refuses the attachment at path when the policy's input.mediaTypes refuse
// its type, or cannot tell it, or nil.
func mediaTypeRefusal(types *policy.MediaTypes, path string, mediaType inputfiles.MediaType, resolveErr error) error {
	switch {
	case types == nil:
		return nil
	case resolveErr != nil:
		return attachmentRefusal(path, " "+resolveErr.Error())
	case !types.Refuses(mediaType.Class, mediaType.Value):
		return nil
	case mediaType.Value == "":
		return attachmentRefusal(path, " has no media type that input.mediaTypes can check; send it inline with its media type")
	}
	return attachmentRefusal(path, " is "+mediaType.Value+", which input.mediaTypes refuses")
}

// attachmentPair is what routing knows, before any plugin is opened, about how a pair reads
// attachments.
type attachmentPair struct {
	selection routingSelection
	// mediaTypes are the policy's input.mediaTypes.
	mediaTypes *policy.MediaTypes
	// extracts turns inline text files into prompt text, as a file or as text depending on the
	// mode. Text extraction is never encrypted.
	extracts bool
	// inspects refuses an attachment that stays opaque: input limited to ASCII, or redaction
	// that the policy holds unencrypted. Encrypted redaction is known only once the pair is
	// prepared, and its checks refuse the attachment then.
	inspects bool
	// managed marks a credential of Stogas, which cannot read a provider file ID.
	managed bool
}

func newAttachmentPair(selection routingSelection, config *policy.Config, managed bool) attachmentPair {
	return attachmentPair{selection: selection, mediaTypes: config.MediaTypes(), extracts: config.TextExtraction() != policy.TextExtractionOff, inspects: config.InspectsInput(), managed: managed}
}

// typeRefusal reports why the pair's policy refuses an attachment's media type, or nil.
func (p attachmentPair) typeRefusal(attachment Attachment) error {
	return mediaTypeRefusal(p.mediaTypes, attachment.Path, attachment.mediaType, attachment.mediaTypeErr)
}

// refusal reports why the pair cannot read an attachment, as the preparation of the pair would
// refuse it, or nil when it can. subject names the deployments in question.
func (p attachmentPair) refusal(attachment Attachment, subject string) error {
	if err := p.typeRefusal(attachment); err != nil {
		return err
	}
	if attachment.text && p.extracts {
		return nil
	}
	if err := attachmentError(p.selection.provider, p.selection.deployment, attachment, subject); err != nil {
		return err
	}
	if attachment.ID != "" && p.managed {
		return attachmentRefusal(attachment.Path, " provider file IDs require BYOK")
	}
	if p.inspects {
		return attachmentRefusal(attachment.Path, " cannot satisfy the active input inspection policy; submit text or enable text extraction for inline UTF-8 text files")
	}
	return nil
}

// reads reports whether the pair reads every attachment.
func (p attachmentPair) reads(attachments []Attachment) bool {
	for _, attachment := range attachments {
		if p.refusal(attachment, routingSubject) != nil {
			return false
		}
	}
	return true
}

// deploymentReads reports whether a deployment reads every attachment that no policy can make
// readable. An inline text file counts as read, since a policy can extract it.
func deploymentReads(attachments []Attachment, selection routingSelection) bool {
	for _, attachment := range attachments {
		if !attachment.text && attachmentError(selection.provider, selection.deployment, attachment, routingSubject) != nil {
			return false
		}
	}
	return true
}

// attachmentsRefusal explains why none of the pairs reads the request's attachments: the first
// attachment that none of them reads, with the first pair's reason, or else that no pair reads
// them all together. Retrying cannot change the answer, so the request ends at once.
func attachmentsRefusal(attachments []Attachment, pairs []attachmentPair) error {
	// split lists the attachments that some pair reads and another does not.
	var split []string
	for _, attachment := range attachments {
		var first error
		read, byType := false, false
		for _, pair := range pairs {
			if err := pair.refusal(attachment, routingSubject); err == nil {
				read = true
			} else if first == nil {
				first, byType = err, pair.typeRefusal(attachment) != nil
			}
		}
		switch {
		case !read:
			refusal := PublicError(first)
			refusal.Code = AttachmentUnsupported
			// Only text extraction makes an inline text file readable where nothing reads it, unless
			// its type is what the policy refuses.
			if attachment.text && !byType && !slices.ContainsFunc(pairs, func(pair attachmentPair) bool { return pair.extracts }) {
				refusal.Message += "; enable text extraction to send it as prompt text"
			}
			return refusal
		case first != nil:
			split = append(split, attachment.Path)
		}
	}
	// Each pair refuses an attachment that another pair reads, so at least two are split.
	if len(split) == 0 {
		return attachmentRefusal(attachments[0].Path, " is not supported by "+routingSubject)
	}
	return APIError{
		StatusCode: http.StatusBadRequest, Code: AttachmentUnsupported, Type: ErrorTypeInvalidRequest, Param: split[0],
		Message: strings.Join(split, ", ") + " are not supported together by " + routingSubject + "; send them in separate requests",
	}
}

// requestAttachments lists the attachments of the request's user messages, so that routing can
// skip the candidates that cannot read them. A part that fails its checks on any deployment,
// such as one with two sources, is left to those checks.
func requestAttachments(raw map[string]json.RawMessage, route Route) []Attachment {
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

// readAttachment reads a content part as its checks do. It reports false for a part that is not
// an attachment, or that the request's preparation refuses on any deployment.
func readAttachment(block map[string]json.RawMessage, path string, responses bool) (Attachment, bool) {
	attachment := Attachment{Path: path, Kind: rawStringValue(block["type"]), Responses: responses}
	holderKey, urlKey, dataKey, idKey, formatKey := "", "", "", "", ""
	document := false
	switch {
	case !responses && attachment.Kind == "image_url":
		holderKey, urlKey = "image_url", "url"
	case responses && attachment.Kind == "input_image":
		urlKey, idKey = "image_url", "file_id"
	case !responses && attachment.Kind == "input_audio":
		holderKey, dataKey, formatKey = "input_audio", "data", "format"
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
	format := read(formatKey, false)
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
	declared, payload := "", ""
	if inline != "" {
		var err error
		if declared, payload, err = inputfiles.ParseInline(inline, attachment.FileType); err != nil {
			return Attachment{}, false
		}
		attachment.text = document && inputfiles.TextMediaType(declared)
	}
	if format != "" {
		declared = inputfiles.AudioMediaType(format)
	}
	attachment.mediaType, attachment.mediaTypeErr = inputfiles.ResolveMediaType(attachment.Kind, declared, payload)
	return attachment, true
}

// attachmentHeadBytes is how much of a long source routing decodes beyond a data URL's header:
// enough for content sniffing to read the same bytes as the request's preparation, however the
// JSON escapes them, which takes at most six bytes for each character.
const attachmentHeadBytes = 6 * inputfiles.SniffChars

// attachmentString reads a member that the checks take only as a string with text, as "" where
// it is absent. A null member fails, as the checks refuse it. head decodes a long value only in
// part, so that routing never copies a file: see stringHead.
func attachmentString(raw json.RawMessage, head bool) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "", true
	}
	if head && len(raw) > attachmentHeadBytes && raw[0] == '"' {
		raw = stringHead(raw)
	}
	var value string
	if err := sonic.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}

// stringHead cuts a JSON string longer than attachmentHeadBytes to what routing reads of it: a
// prefix of at most attachmentHeadBytes, after the comma that ends a data URL's header, since no
// escape holds a comma, that splits no escape and no character.
func stringHead(raw json.RawMessage) json.RawMessage {
	end := attachmentHeadBytes
	if bytes.HasPrefix(raw[1:], []byte("data:")) {
		if comma := bytes.IndexByte(raw, ','); comma >= 0 {
			end += comma + 1
		}
	}
	if end >= len(raw)-1 {
		return raw
	}
	for i := 1; i < end; i++ {
		if raw[i] != '\\' {
			continue
		}
		size := 2
		if raw[i+1] == 'u' {
			size = 6
		}
		if i+size > end {
			end = i
			break
		}
		i += size - 1
	}
	for end > 1 && !utf8.RuneStart(raw[end]) {
		end--
	}
	return append(slices.Clip(raw[:end]), '"')
}
