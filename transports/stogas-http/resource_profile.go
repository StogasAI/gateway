package stogashttp

const (
	// The guest resources must match the measured confidential guest profile.
	// The Go and payload values are explicit starting limits, not formulas that
	// imply a measured workload ratio.
	DefaultGuestMemoryBytes         = int64(16 * 1024 * 1024 * 1024)
	DefaultGuestVCPUCount           = 4
	DefaultGoMemoryLimitBytes       = int64(10 * 1024 * 1024 * 1024)
	DefaultPayloadMemoryBudgetBytes = int64(4 * 1024 * 1024 * 1024)
)
