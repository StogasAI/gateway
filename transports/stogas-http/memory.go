package stogashttp

import (
	"math"
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
	minimumRequestWeightBytes    = int64(512 * 1024)
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
)

type memoryReservationClass uint8

const (
	requestLifetimeMemory memoryReservationClass = iota
	streamStateMemory
	downstreamDeliveryMemory
	confidentialStateMemory
)

type requestMemoryAdmission struct {
	budget               int64
	confidentialHeadroom int64
	// Installed before serving. It only releases independently owned idle state.
	reclaim   func(needed int64) bool
	reclaimMu sync.Mutex

	reserved     atomic.Int64
	peakReserved atomic.Int64

	requestReserved      atomic.Int64
	streamStateReserved  atomic.Int64
	downstreamReserved   atomic.Int64
	confidentialReserved atomic.Int64

	requestFailures      atomic.Uint64
	responseFailures     atomic.Uint64
	streamStateFailures  atomic.Uint64
	downstreamFailures   atomic.Uint64
	confidentialFailures atomic.Uint64
}

type requestMemoryLease struct {
	admission      *requestMemoryAdmission
	parent         *requestMemoryLease
	class          memoryReservationClass
	mu             sync.Mutex
	released       atomic.Bool
	transferred    bool
	weight         int64
	retained       int64
	bodyBytes      int
	structure      int64
	response       int64
	responseFailed atomic.Bool
}

type requestMemoryDiagnostics struct {
	BudgetBytes                      int64  `json:"budgetBytes"`
	ConfidentialHeadroomBytes        int64  `json:"confidentialHeadroomBytes"`
	ConfidentialReservedBytes        int64  `json:"confidentialReservedBytes"`
	ConfidentialReservationFailures  uint64 `json:"confidentialReservationFailures"`
	DownstreamReservationFailures    uint64 `json:"downstreamReservationFailures"`
	DownstreamReservedBytes          int64  `json:"downstreamReservedBytes"`
	MinimumRequestReservationBytes   int64  `json:"minimumRequestReservationBytes"`
	PeakReservedBytes                int64  `json:"peakReservedBytes"`
	ProviderResponseCapacityFailures uint64 `json:"providerResponseCapacityFailures"`
	RequestBodyReservationFactor     int64  `json:"requestBodyReservationFactor"`
	JSONValueReservationBytes        int64  `json:"jsonValueReservationBytes"`
	RequestReservationFailures       uint64 `json:"requestReservationFailures"`
	RequestReservedBytes             int64  `json:"requestReservedBytes"`
	ReservedBytes                    int64  `json:"reservedBytes"`
	Saturated                        bool   `json:"saturated"`
	StreamStateReservationFailures   uint64 `json:"streamStateReservationFailures"`
	StreamStateReservedBytes         int64  `json:"streamStateReservedBytes"`
}

func requestMemoryWeight(bodyBytes int, structure int64) int64 {
	if bodyBytes <= 0 {
		bodyBytes = 0
	}
	if structure < 0 || int64(bodyBytes) > math.MaxInt64/requestBodyReservationFactor || structure > math.MaxInt64-int64(bodyBytes)*requestBodyReservationFactor {
		return math.MaxInt64
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
	return max(1, min(limit, requestMemoryBudgetBytes))
}

func (a *requestMemoryAdmission) budgetBytes() int64 {
	if a == nil || a.budget <= 0 {
		return requestMemoryBudgetBytes
	}
	return a.budget
}

func (a *requestMemoryAdmission) acquire(bodyBytes int) (*requestMemoryLease, bool) {
	weight := requestMemoryWeight(bodyBytes, 0)
	if !a.reserve(requestLifetimeMemory, weight) {
		return nil, false
	}
	return &requestMemoryLease{admission: a, class: requestLifetimeMemory, weight: weight, bodyBytes: bodyBytes}, true
}

func (a *requestMemoryAdmission) newLease(class memoryReservationClass) *requestMemoryLease {
	if a == nil {
		return nil
	}
	return &requestMemoryLease{admission: a, class: class}
}

// A response is already covered by the request's provider reservation. Pin its
// retained state or delivery bytes so those owners can outlive the producer
// without acquiring the same memory again when admission is full.
func (l *requestMemoryLease) newRetainedLease(class memoryReservationClass) *requestMemoryLease {
	if l == nil {
		return nil
	}
	return &requestMemoryLease{admission: l.admission, class: class, parent: l}
}

func (a *requestMemoryAdmission) reserve(class memoryReservationClass, bytes int64) bool {
	return a.reserveWithin(class, bytes, a.budgetBytes())
}

func (a *requestMemoryAdmission) reserveWithin(class memoryReservationClass, bytes, budget int64) bool {
	if a == nil || bytes < 0 {
		return false
	}
	if bytes == 0 {
		return true
	}
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
	case requestLifetimeMemory:
		return &a.requestReserved
	case streamStateMemory:
		return &a.streamStateReserved
	case downstreamDeliveryMemory:
		return &a.downstreamReserved
	case confidentialStateMemory:
		return &a.confidentialReserved
	default:
		panic("invalid memory reservation class")
	}
}

func (a *requestMemoryAdmission) failureCounter(class memoryReservationClass) *atomic.Uint64 {
	switch class {
	case requestLifetimeMemory:
		return &a.requestFailures
	case streamStateMemory:
		return &a.streamStateFailures
	case downstreamDeliveryMemory:
		return &a.downstreamFailures
	case confidentialStateMemory:
		return &a.confidentialFailures
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
	weight := max(requestMemoryWeight(bodyBytes, l.structure+l.response), l.retained)
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
	structure := int64(math.MaxInt64)
	if int64(values) <= math.MaxInt64/requestJSONValueBytes {
		structure = int64(values) * requestJSONValueBytes
	}
	structure = max(l.structure, structure)
	if structure > math.MaxInt64-l.response {
		return errRequestMemoryCapacity
	}
	weight := max(requestMemoryWeight(l.bodyBytes, structure+l.response), l.retained)
	if !l.admission.reserve(l.class, weight-l.weight) {
		return errRequestMemoryCapacity
	}
	l.structure, l.weight = structure, weight
	return nil
}

func (l *requestMemoryLease) ReserveResponse(bytes, values int64) (ok bool) {
	defer func() {
		if !ok {
			l.recordResponseCapacityFailure()
		}
	}()
	if l == nil || l.admission == nil || bytes < 0 || values < 0 ||
		bytes > requestMemoryBudgetBytes/requestBodyReservationFactor || values > requestMemoryBudgetBytes/requestJSONValueBytes {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released.Load() {
		return false
	}
	response := l.response + bytes*requestBodyReservationFactor + values*requestJSONValueBytes
	if response < l.response || response > math.MaxInt64-l.structure {
		return false
	}
	weight := max(requestMemoryWeight(l.bodyBytes, l.structure+response), l.retained)
	if !l.admission.reserve(l.class, weight-l.weight) {
		return false
	}
	l.response, l.weight = response, weight
	return true
}

func (l *requestMemoryLease) ReserveTemporary(bytes int64) (release func(), ok bool) {
	defer func() {
		if !ok {
			l.recordResponseCapacityFailure()
		}
	}()
	if l == nil || l.admission == nil || bytes < 0 || bytes > l.admission.budgetBytes() {
		return nil, false
	}
	lease := l.admission.newLease(streamStateMemory)
	if !lease.grow(int(bytes)) {
		return nil, false
	}
	return lease.release, true
}

// Count affected requests once, including decoder scratch admission. These
// failures can occur after dispatch and overlap the reservation-class counters.
func (l *requestMemoryLease) recordResponseCapacityFailure() {
	if l != nil && l.responseFailed.CompareAndSwap(false, true) && l.admission != nil {
		l.admission.responseFailures.Add(1)
	}
}

// grow reserves one byte for each retained or queued stream payload byte.
// Request parsing uses its separate reservation factor in resize.
func (l *requestMemoryLease) grow(bytes int) bool {
	if l == nil {
		return true
	}
	return l.growWithin(bytes, l.admission.budgetBytes())
}

func (l *requestMemoryLease) growWithin(bytes int, budget int64) bool {
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
	if l.parent != nil {
		if !l.parent.pin(l.class, delta) {
			return false
		}
	} else {
		if !l.admission.reserveWithin(l.class, delta, budget) {
			return false
		}
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
	if l.parent != nil {
		l.parent.unpin(l.class, delta)
	} else {
		l.admission.release(l.class, delta)
	}
}

func (l *requestMemoryLease) release() {
	if l == nil || l.admission == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released.CompareAndSwap(false, true) {
		if l.parent != nil {
			l.parent.unpin(l.class, l.weight-l.retained)
		} else {
			l.admission.release(l.class, l.weight-l.retained)
		}
		l.weight = l.retained
	}
}

func (l *requestMemoryLease) pin(class memoryReservationClass, bytes int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released.Load() || bytes > l.weight-l.retained {
		return false
	}
	l.retained += bytes
	l.admission.reservedCounter(l.class).Add(-bytes)
	l.admission.reservedCounter(class).Add(bytes)
	return true
}

func (l *requestMemoryLease) unpin(class memoryReservationClass, bytes int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.retained -= bytes
	if l.released.Load() {
		l.weight -= bytes
		l.admission.release(class, bytes)
	} else {
		l.admission.reservedCounter(class).Add(-bytes)
		l.admission.reservedCounter(l.class).Add(bytes)
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
		BudgetBytes:                      a.budgetBytes(),
		ConfidentialHeadroomBytes:        a.confidentialHeadroom,
		ConfidentialReservedBytes:        a.confidentialReserved.Load(),
		ConfidentialReservationFailures:  a.confidentialFailures.Load(),
		DownstreamReservationFailures:    a.downstreamFailures.Load(),
		DownstreamReservedBytes:          a.downstreamReserved.Load(),
		MinimumRequestReservationBytes:   minimumRequestWeightBytes,
		PeakReservedBytes:                a.peakReserved.Load(),
		ProviderResponseCapacityFailures: a.responseFailures.Load(),
		RequestBodyReservationFactor:     requestBodyReservationFactor,
		JSONValueReservationBytes:        requestJSONValueBytes,
		RequestReservationFailures:       a.requestFailures.Load(),
		RequestReservedBytes:             a.requestReserved.Load(),
		ReservedBytes:                    a.reserved.Load(),
		Saturated:                        a.saturated(),
		StreamStateReservationFailures:   a.streamStateFailures.Load(),
		StreamStateReservedBytes:         a.streamStateReserved.Load(),
	}
}
