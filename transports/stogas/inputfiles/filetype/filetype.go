// Package filetype names the files that text extraction turns into prompt text: for the policy
// that sets their modes, and for the code that reads them. It reads no file.
package filetype

import (
	"slices"
	"strings"
)

// Family is a family of files that text extraction turns into prompt text. A policy names a
// family to set the mode of all its files.
type Family string

const (
	// Text is a text file, such as CSV, JSON or source code, whose bytes are its text.
	Text Family = "text"
	// Office is a Word, Excel, PowerPoint or OpenDocument file: a zip archive of XML parts,
	// whose text the gateway reads from the parts.
	Office Family = "office"
)

// Families lists every family.
var Families = []Family{Text, Office}

// Type is how a policy names an inline document that text extraction can turn into prompt text.
// The zero value is any other file.
type Type struct {
	Family Family
	// MediaType is the type that the file declares, or without one text/plain for text and the
	// type of the filename's extension for an Office file.
	MediaType string
}

// The Office Open XML and OpenDocument types that text extraction reads, by what a file holds.
// The binary formats of Office 97 to 2003 and encrypted files are not zip archives and stay
// opaque.
var (
	Documents = []string{
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.ms-word.document.macroenabled.12",
		"application/vnd.oasis.opendocument.text",
	}
	Spreadsheets = []string{
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.ms-excel.sheet.macroenabled.12",
		"application/vnd.oasis.opendocument.spreadsheet",
	}
	Presentations = []string{
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"application/vnd.ms-powerpoint.presentation.macroenabled.12",
		"application/vnd.oasis.opendocument.presentation",
	}
)

// FamilyOf names the family that holds a lowercase media type, or "" for a type that text
// extraction does not read.
func FamilyOf(mediaType string) Family {
	switch {
	case slices.Contains(Documents, mediaType), slices.Contains(Spreadsheets, mediaType), slices.Contains(Presentations, mediaType):
		return Office
	case IsText(mediaType):
		return Text
	}
	return ""
}

// IsText reports whether text extraction reads a file of the media type as text: text/*, JSON,
// XML and their suffixes, and the types in use for scripts, data and configuration that are
// plain text.
func IsText(mediaType string) bool {
	mediaType = strings.ToLower(mediaType)
	return strings.HasPrefix(mediaType, "text/") || strings.HasSuffix(mediaType, "+json") || strings.HasSuffix(mediaType, "+xml") ||
		slices.Contains(textApplicationTypes, mediaType)
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
