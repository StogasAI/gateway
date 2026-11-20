package plugins

// Metrics is the fixed, bounded plugin section written to the request log.
// Plugin code must never place source values, hashes, or text offsets here,
// only counts, durations and the closed labels of a classifier.
type Metrics struct {
	TextExtraction *TextExtractionMetrics `json:"text_extraction,omitempty"`
	Redaction      *RedactionMetrics      `json:"redaction,omitempty"`
	Export         *ExportMetrics         `json:"export,omitempty"`
	Classification *ClassificationMetrics `json:"classification,omitempty"`
}

// ClassificationMetrics holds the result of each classifier that the request's policy runs.
type ClassificationMetrics struct {
	Language         *LanguageMetrics         `json:"language,omitempty"`
	HiddenCharacters *HiddenCharactersMetrics `json:"hidden_characters,omitempty"`
}

// LanguageMetrics names the language of the newest user message that holds prose and of the
// reply: a BCP 47 tag, or und when the classifier cannot tell. Each is absent without such text.
type LanguageMetrics struct {
	Input  string `json:"input,omitempty"`
	Output string `json:"output,omitempty"`
}

// HiddenCharactersMetrics counts the hidden characters of the input text and the output text.
type HiddenCharactersMetrics struct {
	Input  uint32 `json:"input"`
	Output uint32 `json:"output"`
}

type TextExtractionMetrics struct {
	FilesExtracted uint32 `json:"files_extracted"`
	DurationUS     uint32 `json:"duration_us"`
}

type ExportMetrics struct {
	DurationUS uint32 `json:"duration_us"`
}

// RedactionMetrics counts the values that redaction replaced in the request and in the
// response, and the values that it put back in the response. The duration is the request's
// scan, which runs before the first provider call.
type RedactionMetrics struct {
	ItemsRedacted         uint32 `json:"items_redacted"`
	ResponseItemsRedacted uint32 `json:"response_items_redacted,omitempty"`
	ItemsRestored         uint32 `json:"items_restored,omitempty"`
	DurationUS            uint32 `json:"duration_us"`
}
