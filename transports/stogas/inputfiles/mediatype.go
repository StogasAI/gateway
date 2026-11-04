package inputfiles

import (
	"encoding/base64"
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
	prefix := payload
	if len(prefix) > SniffChars {
		prefix = prefix[:SniffChars]
	}
	data, err := base64.StdEncoding.Strict().DecodeString(prefix)
	if err != nil || len(data) == 0 {
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
	sniffed := Sniff(payload)
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
	case !sniffedMatches(declared, sniffed):
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

// sniffedMatches reports whether content sniffed as sniffed can be of the declared type.
// Sniffing knows a few signatures, so unknown binary data matches any binary type, text matches
// any text type, and a zip archive matches the formats built on it.
func sniffedMatches(declared, sniffed string) bool {
	switch {
	case sniffed == "application/octet-stream":
		return !TextMediaType(declared)
	case strings.HasPrefix(sniffed, "text/"):
		return TextMediaType(declared)
	case declared == sniffed || slices.Contains(sniffedAliases[sniffed], declared):
		return true
	case sniffed == "application/zip":
		return strings.HasSuffix(declared, "+zip") ||
			strings.HasPrefix(declared, "application/vnd.openxmlformats-officedocument.") ||
			strings.HasPrefix(declared, "application/vnd.oasis.opendocument.") ||
			strings.HasPrefix(declared, "application/vnd.ms-") && strings.HasSuffix(declared, ".macroenabled.12") ||
			slices.Contains(zipFormats, declared)
	}
	return false
}

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
