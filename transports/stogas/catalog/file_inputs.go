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
	// Chat Completions, which a bridged deployment gets, has no image file IDs or file URLs.
	bridged := attachment.Responses && deployment.bridges(RouteResponses)
	modality := ""
	switch attachment.Kind {
	case "image_url", "input_image":
		modality = "image"
		if attachment.Kind == "input_image" && attachment.ID != "" && (claude || bridged) {
			return attachmentRefusal(attachment.Path, " image file IDs are not supported by "+subject)
		}
	case "input_audio":
		modality = "audio"
	case "file", "input_file":
		if bridged && attachment.URL != "" {
			return attachmentRefusal(attachment.Path, " file URLs are not supported by "+subject)
		}
		if err := documentError(claude, deployment.DocumentFormats, attachment, subject); err != nil {
			return err
		}
	}
	if modality != "" && !slices.Contains(deployment.InputModalities, modality) {
		return attachmentRefusal(attachment.Path, " "+modality+" input is not supported by "+subject)
	}
	// A Claude file ID names a file in the Files API of Anthropic's own platform, which Claude that
	// a cloud hosts, on Azure too, lacks.
	if claude && attachment.ID != "" && deployment.Upstream.Hosting != "anthropic" {
		return attachmentRefusal(attachment.Path, " file IDs are not supported by "+subject)
	}
	// Claude that AWS or Google runs fetches no URL.
	if CloudRunsClaude(provider, deployment) && attachment.URL != "" && !strings.HasPrefix(attachment.URL, "data:") {
		return attachmentRefusal(attachment.Path, " URLs are not supported by "+subject+"; send the content inline")
	}
	return nil
}

func documentError(claude bool, formats DocumentFormats, attachment Attachment, subject string) error {
	path := attachment.Path
	if attachment.URL != "" && !attachment.Responses && !claude {
		return attachmentRefusal(path, " file URLs on Chat Completions are not supported by "+subject+"; send the file in file_data or use Responses")
	}
	if attachment.FileType != "" && !claude {
		return attachmentRefusal(path, " file_type is not supported by "+subject+"; name the media type in a base64 data URL")
	}
	if len(formats.MediaTypes) == 0 {
		return attachmentRefusal(path, " documents are not supported by "+subject)
	}
	if attachment.Data == "" {
		return nil
	}
	extension := strings.ToLower(filepath.Ext(attachment.Filename))
	mediaType, _, err := inputfiles.ParseInline(attachment.Data, attachment.FileType)
	if err != nil {
		return APIError{StatusCode: http.StatusBadRequest, Type: ErrorTypeInvalidRequest, Message: path + " " + err.Error(), Param: path}
	}
	if mediaType != "" && mediaType != "application/octet-stream" {
		if !slices.Contains(formats.MediaTypes, mediaType) {
			return attachmentRefusal(path, " is "+mediaType+", which is not supported by "+subject)
		}
	} else if !slices.Contains(formats.Extensions, extension) {
		return attachmentRefusal(path, " has no media type, and its filename extension is not supported by "+subject)
	}
	// Core sends untyped raw base64 to Claude as a PDF, and a raw file_type text/plain as literal
	// text, and Anthropic reads no application/octet-stream document.
	if claude && (mediaType == "application/octet-stream" || (!strings.HasPrefix(attachment.Data, "data:") && mediaType != "application/pdf" && !(mediaType == "" && extension == ".pdf"))) {
		return attachmentRefusal(path, " needs a base64 data URL that names its media type, such as application/pdf, for "+subject)
	}
	return nil
}

// AttachmentUnsupported is the code of a request whose attachment no candidate deployment reads.
const AttachmentUnsupported = "attachment_unsupported"

// attachmentRefusal refuses the attachment at path for reason, which follows the path.
func attachmentRefusal(path, reason string) error {
	return APIError{StatusCode: http.StatusBadRequest, Code: AttachmentUnsupported, Type: ErrorTypeInvalidRequest, Message: path + reason, Param: path}
}

// ManagedFileIDRefusal refuses a provider file ID that a credential of Stogas would send. A file
// ID names a file in the account that holds it, which is never Stogas's.
func ManagedFileIDRefusal(path string) error {
	return attachmentRefusal(path, " is a provider file ID, which only a BYOK credential can read")
}

// fileIDAccounts refuses a request with a provider file ID that more than one credential could
// serve. A file ID names a file in the account that holds it, and nothing tells which credential
// that is, so routing must not choose one.
func fileIDAccounts(attachment Attachment, candidates []*ResolvedRequest, credentials map[*ResolvedRequest][]int) error {
	seen := make(map[credentialCandidate]bool)
	// providers lists the providers of the credentials in candidate order, and counts their
	// credentials.
	var providers []schemas.ModelProvider
	counts := make(map[schemas.ModelProvider]int)
	for _, candidate := range candidates {
		for _, index := range credentials[candidate] {
			key := credentialCandidate{candidate.Provider, index}
			if seen[key] {
				continue
			}
			seen[key] = true
			if counts[key.provider] == 0 {
				providers = append(providers, key.provider)
			}
			counts[key.provider]++
		}
	}
	if len(seen) <= 1 {
		return nil
	}
	fix := "use a key with one credential for this model"
	// Naming a provider helps only where it leaves one credential.
	if i := slices.IndexFunc(providers, func(provider schemas.ModelProvider) bool { return counts[provider] == 1 }); i >= 0 {
		fix = "name the provider in the model, such as provider:" + string(providers[i]) + ", or " + fix
	}
	return attachmentRefusal(attachment.Path, fmt.Sprintf(" is a provider file ID, which only the credential of the account that holds the file can read, and this request can use %d credentials; %s", len(seen), fix))
}

// inputCheckRefusal refuses the attachment at path, which setting, input.asciiOnly or
// plugins.redaction, cannot check, since it reads only text.
func inputCheckRefusal(path, setting string) error {
	return attachmentRefusal(path, " is an attachment, which "+setting+" cannot check")
}

// textExtractionHint ends the refusal of an inline text file that a pair without text extraction
// cannot read. Text extraction turns the file into text, which every deployment and input check
// reads.
const textExtractionHint = ". Turn on plugins.textExtraction to send it as text"

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
	// check names the setting that refuses an attachment that stays opaque, input.asciiOnly or
	// plugins.redaction, or is "".
	check string
}

func newAttachmentPair(selection routingSelection, config *policy.Config) attachmentPair {
	return attachmentPair{selection: selection, mediaTypes: config.MediaTypes(), extracts: config.TextExtraction() != policy.TextExtractionOff, check: config.InputCheck()}
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
	if p.check != "" {
		return inputCheckRefusal(attachment.Path, p.check)
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

// attachmentReason is a refusal that pairs give an attachment, with their deployments.
type attachmentReason struct {
	pair        attachmentPair
	message     string
	deployments []string
}

// attachmentsRefusal explains why none of the pairs reads the request's attachments: the first
// attachment that none of them reads, with the reasons of the pairs, or else that no pair reads
// them all together. Retrying cannot change the answer, so the request ends at once.
func attachmentsRefusal(attachments []Attachment, pairs []attachmentPair) error {
	// split lists the attachments that some pair reads and another does not. Each pair refuses an
	// attachment, so when every attachment has a reader, at least two are split.
	var split []string
	for _, attachment := range attachments {
		var reasons []attachmentReason
		read := false
		for _, pair := range pairs {
			err := pair.refusal(attachment, routingSubject)
			if err == nil {
				read = true
				continue
			}
			message := PublicError(err).Message
			i := slices.IndexFunc(reasons, func(reason attachmentReason) bool { return reason.message == message })
			if i < 0 {
				i = len(reasons)
				reasons = append(reasons, attachmentReason{pair: pair, message: message})
			}
			if id := pair.selection.deployment.ID; !slices.Contains(reasons[i].deployments, id) {
				reasons[i].deployments = append(reasons[i].deployments, id)
			}
		}
		switch {
		case !read:
			return unreadAttachment(attachment, reasons)
		case len(reasons) > 0:
			split = append(split, attachment.Path)
		}
	}
	return APIError{
		StatusCode: http.StatusBadRequest, Code: AttachmentUnsupported, Type: ErrorTypeInvalidRequest, Param: split[0],
		Message: strings.Join(split, ", ") + " are not supported together by " + routingSubject + "; send them in separate requests",
	}
}

// unreadAttachment refuses an attachment that no pair reads. Where the pairs give one reason, it
// names every deployment that this request can use, and otherwise each reason names the
// deployments that give it, so that the refusal holds for every pair.
func unreadAttachment(attachment Attachment, reasons []attachmentReason) error {
	refusal := PublicError(reasons[0].pair.refusal(attachment, routingSubject))
	if len(reasons) > 1 {
		messages := make([]string, len(reasons))
		for i, reason := range reasons {
			slices.Sort(reason.deployments)
			messages[i] = PublicError(reason.pair.refusal(attachment, namedIDs(reason.deployments))).Message
		}
		refusal.Message = strings.Join(messages, ". ")
	}
	// Text extraction makes an inline text file readable to every pair whose policy allows its
	// type, and a pair that extracts it reads it.
	if attachment.text && slices.ContainsFunc(reasons, func(reason attachmentReason) bool { return reason.pair.typeRefusal(attachment) == nil }) {
		refusal.Message += textExtractionHint
	}
	return refusal
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
