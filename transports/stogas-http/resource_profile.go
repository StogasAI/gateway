package stogashttp

const (
	// The guest resources must match the measured confidential guest profile.
	// Admission covers Go payloads and native owners. These limits overlap;
	// they are not independent physical memory partitions.
	DefaultGuestMemoryBytes         = int64(16 * 1024 * 1024 * 1024)
	DefaultGuestVCPUCount           = 4
	DefaultGoMemoryLimitBytes       = int64(8 * 1024 * 1024 * 1024)
	DefaultPayloadMemoryBudgetBytes = int64(8 * 1024 * 1024 * 1024)
)
