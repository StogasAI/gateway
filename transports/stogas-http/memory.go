package stogashttp

import (
	"runtime/debug"
	"sync"
	"sync/atomic"
	"unsafe"

	openaiprovider "github.com/maximhq/bifrost/core/providers/openai"
	"github.com/maximhq/bifrost/core/schemas"
)

const (
	requestMemoryBudgetBytes = DefaultPayloadMemoryBudgetBytes
	// This factor is conservative admission accounting for parsing and
	// normalization. It does not allocate or prove five in-memory copies.
	requestBodyReservationFactor = int64(5)
	minimumRequestWeightBytes    = int64(1 * 1024 * 1024)
	// Wire bytes alone miss dense arrays of empty or short values. Charge each
	// JSON value at the largest fixed input-item size before typed decoding.
	// This is admission accounting, not a bound on every Go allocation or RSS.
	requestJSONValueBytes = int64(max(
		unsafe.Sizeof(openaiprovider.OpenAIMessage{}),
		unsafe.Sizeof(schemas.ChatMessage{}),
		unsafe.Sizeof(schemas.ResponsesMessage{}),
		unsafe.Sizeof(schemas.ChatContentBlock{}),
		unsafe.Sizeof(schemas.ResponsesMessageContentBlock{}),
	))
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
	// Installed before serving. It only releases independently owned idle state.
	reclaim   func(needed int64) bool
	reclaimMu sync.Mutex

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
	retained    int64
	bodyBytes   int
	structure   int64
}

type requestMemoryDiagnostics struct {
	BudgetBytes                    int64  `json:"budgetBytes"`
	DownstreamReservationFailures  uint64 `json:"downstreamReservationFailures"`
	DownstreamReservedBytes        int64  `json:"downstreamReservedBytes"`
	MinimumRequestReservationBytes int64  `json:"minimumRequestReservationBytes"`
	PeakReservedBytes              int64  `json:"peakReservedBytes"`
	RequestBodyReservationFactor   int64  `json:"requestBodyReservationFactor"`
	JSONValueReservationBytes      int64  `json:"jsonValueReservationBytes"`
	RequestBodyReservationFailures uint64 `json:"requestBodyReservationFailures"`
	RequestBodyReservedBytes       int64  `json:"requestBodyReservedBytes"`
	ReservedBytes                  int64  `json:"reservedBytes"`
	Saturated                      bool   `json:"saturated"`
	StreamStateReservationFailures uint64 `json:"streamStateReservationFailures"`
	StreamStateReservedBytes       int64  `json:"streamStateReservedBytes"`
}

func requestMemoryWeight(bodyBytes int, structure int64) int64 {
	if bodyBytes <= 0 {
		bodyBytes = 0
	}
	if int64(bodyBytes) > requestMemoryBudgetBytes/requestBodyReservationFactor || structure > requestMemoryBudgetBytes-int64(bodyBytes)*requestBodyReservationFactor {
		return requestMemoryBudgetBytes + 1
	}
	weight := int64(bodyBytes)*requestBodyReservationFactor + structure
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
	weight := requestMemoryWeight(bodyBytes, 0)
	if !a.reserve(requestBodyMemory, weight) {
		return nil, false
	}
	return &requestMemoryLease{admission: a, class: requestBodyMemory, weight: weight, bodyBytes: bodyBytes}, true
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
	reclaimed := false
	for {
		current := a.reserved.Load()
		if bytes > budget || current > budget-bytes {
			if bytes <= budget && !reclaimed && a.reclaim != nil {
				reclaimed = true
				if a.reclaimMu.TryLock() {
					// Recheck after winning reclamation: another caller may have
					// already released enough idle state for this reservation.
					needed := a.reserved.Load() - (budget - bytes)
					freed := needed <= 0 || a.reclaim(needed)
					a.reclaimMu.Unlock()
					if freed {
						continue
					}
				}
			}
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
	weight := max(requestMemoryWeight(bodyBytes, l.structure), l.retained)
	delta := weight - l.weight
	if delta == 0 {
		l.bodyBytes = bodyBytes
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
	l.bodyBytes = bodyBytes
	return true
}

// The structure charge follows the original request lease through inference,
// including cancellation and provider draining; body resizing cannot release it.
func (l *requestMemoryLease) admitJSON(values int) error {
	if l == nil || l.admission == nil || values < 0 {
		return errRequestMemoryCapacity
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released.Load() {
		return errRequestMemoryCapacity
	}
	structure := requestMemoryBudgetBytes + 1
	if int64(values) <= requestMemoryBudgetBytes/requestJSONValueBytes {
		structure = int64(values) * requestJSONValueBytes
	}
	structure = max(l.structure, structure)
	weight := max(requestMemoryWeight(l.bodyBytes, structure), l.retained)
	if !l.admission.reserve(l.class, weight-l.weight) {
		return errRequestMemoryCapacity
	}
	l.structure, l.weight = structure, weight
	return nil
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
	if delta > l.weight-l.retained {
		delta = l.weight - l.retained
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
		l.admission.release(l.class, l.weight-l.retained)
		l.weight = l.retained
	}
}

// retain transfers ownership of part of an existing reservation. The live
// request keeps its full charge until release; afterward only retained bytes
// remain. No admission/reacquisition race can discard a settlement under load.
// The returned closure retains this small lease, never the request or body.
func (l *requestMemoryLease) retain(bytes int) (func(), bool) {
	if l == nil || l.admission == nil || bytes <= 0 {
		return nil, false
	}
	l.mu.Lock()
	if l.released.Load() || int64(bytes) > l.weight-l.retained {
		l.mu.Unlock()
		return nil, false
	}
	l.retained += int64(bytes)
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.retained -= int64(bytes)
			if l.released.Load() {
				l.weight -= int64(bytes)
				l.admission.release(l.class, int64(bytes))
			}
		})
	}, true
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
			JSONValueReservationBytes:      requestJSONValueBytes,
		}
	}
	return requestMemoryDiagnostics{
		BudgetBytes:                    a.budgetBytes(),
		DownstreamReservationFailures:  a.downstreamFailures.Load(),
		DownstreamReservedBytes:        a.downstreamReserved.Load(),
		MinimumRequestReservationBytes: minimumRequestWeightBytes,
		PeakReservedBytes:              a.peakReserved.Load(),
		RequestBodyReservationFactor:   requestBodyReservationFactor,
		JSONValueReservationBytes:      requestJSONValueBytes,
		RequestBodyReservationFailures: a.requestBodyFailures.Load(),
		RequestBodyReservedBytes:       a.requestBodyReserved.Load(),
		ReservedBytes:                  a.reserved.Load(),
		Saturated:                      a.saturated(),
		StreamStateReservationFailures: a.streamStateFailures.Load(),
		StreamStateReservedBytes:       a.streamStateReserved.Load(),
	}
}
