package stogashttp

import (
	"runtime/debug"
	"sync"
	"sync/atomic"
)

const (
	requestMemoryBudgetBytes = DefaultPayloadMemoryBudgetBytes
	// This factor is conservative admission accounting for parsing and
	// normalization. It does not allocate or prove five in-memory copies.
	requestBodyReservationFactor = int64(5)
	minimumRequestWeightBytes    = int64(1 * 1024 * 1024)
	// Four GiB out of the ten-GiB default Go limit reduces to two fifths.
	// These small values keep lower-limit scaling within int64.
	lowerGoLimitBudgetNumerator   = int64(2)
	lowerGoLimitBudgetDenominator = int64(5)
)

type memoryReservationClass uint8

const (
	requestBodyMemory memoryReservationClass = iota
	streamStateMemory
	downstreamDeliveryMemory
)

type requestMemoryAdmission struct {
	budget int64

	reserved     atomic.Int64
	peakReserved atomic.Int64

	requestBodyReserved atomic.Int64
	streamStateReserved atomic.Int64
	downstreamReserved  atomic.Int64

	requestBodyFailures atomic.Uint64
	streamStateFailures atomic.Uint64
	downstreamFailures  atomic.Uint64
}

type requestMemoryLease struct {
	admission   *requestMemoryAdmission
	class       memoryReservationClass
	mu          sync.Mutex
	released    atomic.Bool
	transferred bool
	weight      int64
}

type requestMemoryDiagnostics struct {
	BudgetBytes                    int64  `json:"budgetBytes"`
	DownstreamReservationFailures  uint64 `json:"downstreamReservationFailures"`
	DownstreamReservedBytes        int64  `json:"downstreamReservedBytes"`
	MinimumRequestReservationBytes int64  `json:"minimumRequestReservationBytes"`
	PeakReservedBytes              int64  `json:"peakReservedBytes"`
	RequestBodyReservationFactor   int64  `json:"requestBodyReservationFactor"`
	RequestBodyReservationFailures uint64 `json:"requestBodyReservationFailures"`
	RequestBodyReservedBytes       int64  `json:"requestBodyReservedBytes"`
	ReservedBytes                  int64  `json:"reservedBytes"`
	Saturated                      bool   `json:"saturated"`
	StreamStateReservationFailures uint64 `json:"streamStateReservationFailures"`
	StreamStateReservedBytes       int64  `json:"streamStateReservedBytes"`
}

func requestMemoryWeight(bodyBytes int) int64 {
	if bodyBytes <= 0 {
		return minimumRequestWeightBytes
	}
	if int64(bodyBytes) > requestMemoryBudgetBytes/requestBodyReservationFactor {
		return requestMemoryBudgetBytes + 1
	}
	weight := int64(bodyBytes) * requestBodyReservationFactor
	if weight < minimumRequestWeightBytes {
		return minimumRequestWeightBytes
	}
	return weight
}

func newRequestMemoryAdmission() *requestMemoryAdmission {
	return &requestMemoryAdmission{budget: requestMemoryBudgetForGoLimit(debug.SetMemoryLimit(-1))}
}

func requestMemoryBudgetForGoLimit(limit int64) int64 {
	if limit <= 0 {
		return 1
	}
	if limit >= DefaultGoMemoryLimitBytes {
		return requestMemoryBudgetBytes
	}
	budget := limit/lowerGoLimitBudgetDenominator*lowerGoLimitBudgetNumerator +
		limit%lowerGoLimitBudgetDenominator*lowerGoLimitBudgetNumerator/lowerGoLimitBudgetDenominator
	if budget < 1 {
		return 1
	}
	return budget
}

func (a *requestMemoryAdmission) budgetBytes() int64 {
	if a == nil || a.budget <= 0 {
		return requestMemoryBudgetBytes
	}
	return a.budget
}

func (a *requestMemoryAdmission) acquire(bodyBytes int) (*requestMemoryLease, bool) {
	weight := requestMemoryWeight(bodyBytes)
	if !a.reserve(requestBodyMemory, weight) {
		return nil, false
	}
	return &requestMemoryLease{admission: a, class: requestBodyMemory, weight: weight}, true
}

func (a *requestMemoryAdmission) newLease(class memoryReservationClass) *requestMemoryLease {
	if a == nil {
		return nil
	}
	return &requestMemoryLease{admission: a, class: class}
}

func (a *requestMemoryAdmission) reserve(class memoryReservationClass, bytes int64) bool {
	if a == nil || bytes < 0 {
		return false
	}
	if bytes == 0 {
		return true
	}
	budget := a.budgetBytes()
	for {
		current := a.reserved.Load()
		if bytes > budget || current > budget-bytes {
			a.failureCounter(class).Add(1)
			return false
		}
		if a.reserved.CompareAndSwap(current, current+bytes) {
			a.reservedCounter(class).Add(bytes)
			a.recordPeak(current + bytes)
			return true
		}
	}
}

func (a *requestMemoryAdmission) release(class memoryReservationClass, bytes int64) {
	if a == nil || bytes <= 0 {
		return
	}
	a.reservedCounter(class).Add(-bytes)
	a.reserved.Add(-bytes)
}

func (a *requestMemoryAdmission) recordPeak(value int64) {
	for {
		peak := a.peakReserved.Load()
		if value <= peak || a.peakReserved.CompareAndSwap(peak, value) {
			return
		}
	}
}

func (a *requestMemoryAdmission) reservedCounter(class memoryReservationClass) *atomic.Int64 {
	switch class {
	case requestBodyMemory:
		return &a.requestBodyReserved
	case streamStateMemory:
		return &a.streamStateReserved
	case downstreamDeliveryMemory:
		return &a.downstreamReserved
	default:
		panic("invalid memory reservation class")
	}
}

func (a *requestMemoryAdmission) failureCounter(class memoryReservationClass) *atomic.Uint64 {
	switch class {
	case requestBodyMemory:
		return &a.requestBodyFailures
	case streamStateMemory:
		return &a.streamStateFailures
	case downstreamDeliveryMemory:
		return &a.downstreamFailures
	default:
		panic("invalid memory reservation class")
	}
}

func (l *requestMemoryLease) resize(bodyBytes int) bool {
	if l == nil || l.admission == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released.Load() {
		return false
	}
	weight := requestMemoryWeight(bodyBytes)
	delta := weight - l.weight
	if delta == 0 {
		return true
	}
	if delta > 0 {
		if !l.admission.reserve(l.class, delta) {
			return false
		}
	} else {
		l.admission.release(l.class, -delta)
	}
	l.weight = weight
	return true
}

// grow reserves one byte for each retained or queued stream payload byte.
// Request parsing uses its separate reservation factor in resize.
func (l *requestMemoryLease) grow(bytes int) bool {
	if l == nil {
		return true
	}
	if l.admission == nil || bytes < 0 {
		return false
	}
	if bytes == 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released.Load() {
		return false
	}
	delta := int64(bytes)
	if !l.admission.reserve(l.class, delta) {
		return false
	}
	l.weight += delta
	return true
}

func (l *requestMemoryLease) shrink(bytes int) {
	if l == nil || l.admission == nil || bytes <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released.Load() {
		return
	}
	delta := int64(bytes)
	if delta > l.weight {
		delta = l.weight
	}
	l.weight -= delta
	l.admission.release(l.class, delta)
}

func (l *requestMemoryLease) release() {
	if l == nil || l.admission == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released.CompareAndSwap(false, true) {
		l.admission.release(l.class, l.weight)
	}
}

// saturated reports only when the admission budget cannot fit the smallest
// request reservation. It does not add a separate speculative headroom rule.
func (a *requestMemoryAdmission) saturated() bool {
	if a == nil {
		return false
	}
	return a.reserved.Load() > a.budgetBytes()-minimumRequestWeightBytes
}

func (a *requestMemoryAdmission) diagnostics() requestMemoryDiagnostics {
	if a == nil {
		return requestMemoryDiagnostics{
			BudgetBytes:                    requestMemoryBudgetBytes,
			MinimumRequestReservationBytes: minimumRequestWeightBytes,
			RequestBodyReservationFactor:   requestBodyReservationFactor,
		}
	}
	return requestMemoryDiagnostics{
		BudgetBytes:                    a.budgetBytes(),
		DownstreamReservationFailures:  a.downstreamFailures.Load(),
		DownstreamReservedBytes:        a.downstreamReserved.Load(),
		MinimumRequestReservationBytes: minimumRequestWeightBytes,
		PeakReservedBytes:              a.peakReserved.Load(),
		RequestBodyReservationFactor:   requestBodyReservationFactor,
		RequestBodyReservationFailures: a.requestBodyFailures.Load(),
		RequestBodyReservedBytes:       a.requestBodyReserved.Load(),
		ReservedBytes:                  a.reserved.Load(),
		Saturated:                      a.saturated(),
		StreamStateReservationFailures: a.streamStateFailures.Load(),
		StreamStateReservedBytes:       a.streamStateReserved.Load(),
	}
}
