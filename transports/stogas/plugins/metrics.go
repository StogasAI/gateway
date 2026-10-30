package plugins

// Metrics is the fixed, bounded plugin section written to the request log.
// Plugin code must never place source values, hashes, or text offsets here.
type Metrics struct {
	Redaction *RedactionMetrics `json:"redaction,omitempty"`
	Export    *ExportMetrics    `json:"export,omitempty"`
}

type ExportMetrics struct {
	DurationUS uint32 `json:"duration_us"`
}

type RedactionMetrics struct {
	ItemsRedacted uint32 `json:"items_redacted"`
	DurationUS    uint32 `json:"duration_us"`
}
