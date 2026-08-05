package stogashttp

import "sync/atomic"

const (
	requestMemoryAmplification = int64(5)
	requestMemoryBudgetBytes   = int64(4 * 1024 * 1024 * 1024)
	minimumRequestWeightBytes  = int64(1 * 1024 * 1024)
)

type requestMemoryAdmission struct {
	used atomic.Int64
}

type requestMemoryDiagnostics struct {
	BudgetBytes int64 `json:"budgetBytes"`
	Pressured   bool  `json:"pressured"`
	UsedBytes   int64 `json:"usedBytes"`
}

func (a *requestMemoryAdmission) acquire(bodyBytes int) (func(), bool) {
	weight := int64(bodyBytes) * requestMemoryAmplification
	if weight < minimumRequestWeightBytes {
		weight = minimumRequestWeightBytes
	}
	for {
		current := a.used.Load()
		if weight > requestMemoryBudgetBytes || current > requestMemoryBudgetBytes-weight {
			return nil, false
		}
		if a.used.CompareAndSwap(current, current+weight) {
			var released atomic.Bool
			return func() {
				if released.CompareAndSwap(false, true) {
					a.used.Add(-weight)
				}
			}, true
		}
	}
}

func (a *requestMemoryAdmission) pressured() bool {
	return a != nil && a.used.Load() >= requestMemoryBudgetBytes*9/10
}

func (a *requestMemoryAdmission) diagnostics() requestMemoryDiagnostics {
	used := int64(0)
	if a != nil {
		used = a.used.Load()
	}
	return requestMemoryDiagnostics{
		BudgetBytes: requestMemoryBudgetBytes,
		Pressured:   used >= requestMemoryBudgetBytes*9/10,
		UsedBytes:   used,
	}
}
