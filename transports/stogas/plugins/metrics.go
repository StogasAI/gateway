package plugins

// Metrics is the fixed, bounded plugin section written to the request log.
// Plugin code must never place source values, hashes, or text offsets here.
type Metrics struct {
	StogasStructuredPIIRedaction *StogasStructuredPIIRedactionMetrics `json:"stogas_structured_pii_redaction,omitempty"`
	StogasExport                 *StogasExportMetrics                 `json:"stogas_export,omitempty"`
}

type StogasExportMetrics struct {
	CaptureUS uint32 `json:"capture_us"`
}

type StogasStructuredPIIRedactionMetrics struct {
	ItemsRedacted uint32 `json:"items_redacted"`
	DurationUS    uint32 `json:"duration_us"`
}
