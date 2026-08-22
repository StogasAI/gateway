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

type requestMemoryLease struct {
	admission   *requestMemoryAdmission
	released    atomic.Bool
	transferred bool
	weight      int64
}

type requestMemoryDiagnostics struct {
	BudgetBytes int64 `json:"budgetBytes"`
	Pressured   bool  `json:"pressured"`
	UsedBytes   int64 `json:"usedBytes"`
}

func requestMemoryWeight(bodyBytes int) int64 {
	if bodyBytes <= 0 {
		return minimumRequestWeightBytes
	}
	if int64(bodyBytes) > requestMemoryBudgetBytes/requestMemoryAmplification {
		return requestMemoryBudgetBytes + 1
	}
	weight := int64(bodyBytes) * requestMemoryAmplification
	if weight < minimumRequestWeightBytes {
		return minimumRequestWeightBytes
	}
	return weight
}

func (a *requestMemoryAdmission) acquire(bodyBytes int) (*requestMemoryLease, bool) {
	weight := requestMemoryWeight(bodyBytes)
	for {
		current := a.used.Load()
		if weight > requestMemoryBudgetBytes || current > requestMemoryBudgetBytes-weight {
			return nil, false
		}
		if a.used.CompareAndSwap(current, current+weight) {
			return &requestMemoryLease{admission: a, weight: weight}, true
		}
	}
}

func (l *requestMemoryLease) resize(bodyBytes int) bool {
	if l == nil || l.admission == nil || l.released.Load() {
		return false
	}
	weight := requestMemoryWeight(bodyBytes)
	delta := weight - l.weight
	if delta == 0 {
		return true
	}
	for {
		current := l.admission.used.Load()
		if delta > 0 && (delta > requestMemoryBudgetBytes || current > requestMemoryBudgetBytes-delta) {
			return false
		}
		if l.admission.used.CompareAndSwap(current, current+delta) {
			l.weight = weight
			return true
		}
	}
}

func (l *requestMemoryLease) release() {
	if l != nil && l.admission != nil && l.released.CompareAndSwap(false, true) {
		l.admission.used.Add(-l.weight)
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
