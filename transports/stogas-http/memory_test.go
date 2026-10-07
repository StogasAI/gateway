package stogashttp

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestJSONStructureRejectionFitsAlreadyAdmittedScanMemory(t *testing.T) {
	for _, escaped := range []bool{false, true} {
		var input strings.Builder
		input.WriteByte('{')
		for index := range 100_000 {
			if index != 0 {
				input.WriteByte(',')
			}
			if escaped {
				fmt.Fprintf(&input, `"\u006b%x":0`, index)
			} else {
				fmt.Fprintf(&input, `"%x":0`, index)
			}
		}
		input.WriteByte('}')
		body := []byte(input.String())
		admission := &requestMemoryAdmission{budget: requestMemoryWeight(len(body), 0)}
		lease, ok := admission.acquire(len(body))
		if !ok {
			t.Fatal("body admission failed")
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		fields, err := catalog.DecodeRequestBody(body, lease.admitJSON)
		runtime.ReadMemStats(&after)
		if !errors.Is(err, errRequestMemoryCapacity) || fields != nil {
			t.Fatalf("structure admission should reject: %v", err)
		}
		// Total allocation is a conservative upper bound on retained scratch.
		// Field/name maps used to exceed this allowance before rejection.
		allocated := after.TotalAlloc - before.TotalAlloc
		scratchBudget := uint64(admission.budget - int64(len(body)))
		if allocated > scratchBudget {
			t.Fatalf("escaped=%v: scan allocated %d bytes before admission; scratch budget %d", escaped, allocated, scratchBudget)
		}
		lease.release()
		if admission.reserved.Load() != 0 {
			t.Fatal("rejected structure retained its reservation")
		}
	}
}

func TestJSONStructureReservationSurvivesBodyResizeAndTransfersOnlyRetainedWork(t *testing.T) {
	const values = 10000
	admission := &requestMemoryAdmission{budget: 2 * int64(values) * requestJSONValueBytes}
	lease, _ := admission.acquire(1024)
	if err := lease.admitJSON(values); err != nil {
		t.Fatal(err)
	}
	before := admission.reserved.Load()
	if err := lease.admitJSON(values); err != nil || admission.reserved.Load() != before {
		t.Fatal("repeated JSON inspection multiplied its reservation")
	}
	if err := lease.admitJSON(int(requestMemoryBudgetBytes)); !errors.Is(err, errRequestMemoryCapacity) || admission.reserved.Load() != before {
		t.Fatal("failed JSON admission changed existing reservations")
	}
	if !lease.resize(4096) || admission.reserved.Load() <= before {
		t.Fatal("body growth lost the structure reservation")
	}
	if !lease.resize(0) || admission.reserved.Load() <= minimumRequestWeightBytes {
		t.Fatal("body release dropped still-live typed objects")
	}
	if err := lease.admitJSON(1); err != nil || admission.reserved.Load() != int64(values)*requestJSONValueBytes {
		t.Fatal("smaller inspection released still-live typed objects")
	}
	release, ok := lease.retain(100)
	if !ok {
		t.Fatal("cannot retain compact accounting")
	}
	lease.release()
	if admission.reserved.Load() != 100 || lease.admitJSON(values) == nil {
		t.Fatal("finished request retained typed objects or accepted new work")
	}
	release()
	if admission.reserved.Load() != 0 {
		t.Fatal("structure reservation leaked")
	}
}

func TestCompetingJSONStructureAdmissionsCannotOvercommit(t *testing.T) {
	const values = 10000
	admission := &requestMemoryAdmission{budget: requestMemoryWeight(0, int64(values)*requestJSONValueBytes) + minimumRequestWeightBytes}
	var leases []*requestMemoryLease
	for range 2 {
		lease, ok := admission.acquire(0)
		if !ok {
			t.Fatal("byte-only request admission failed")
		}
		leases = append(leases, lease)
	}
	var admitted atomic.Int64
	var workers sync.WaitGroup
	for _, lease := range leases {
		workers.Go(func() {
			if lease.admitJSON(values) == nil {
				admitted.Add(1)
			}
		})
	}
	workers.Wait()
	if admitted.Load() != 1 || admission.reserved.Load() > admission.budget {
		t.Fatal("competing structure allocations exceeded the shared budget")
	}
	for _, lease := range leases {
		lease.release()
	}
	if admission.reserved.Load() != 0 {
		t.Fatal("competing structure admission leaked reservations")
	}
}

func TestMemoryPressureReclaimsOnceAndRechecksTheSharedBudget(t *testing.T) {
	for _, release := range []bool{true, false} {
		admission := &requestMemoryAdmission{budget: 100}
		if !admission.reserve(streamStateMemory, 80) {
			t.Fatal("reserve")
		}
		calls := 0
		admission.reclaim = func(needed int64) bool {
			calls++
			if needed != 30 {
				t.Fatalf("reclaimed more than needed: %d", needed)
			}
			if release {
				admission.release(streamStateMemory, 30)
			}
			return true
		}
		if admission.reserve(requestLifetimeMemory, 101) || calls != 0 {
			t.Fatal("impossible reservation must not evict")
		}
		if got := admission.reserve(requestLifetimeMemory, 50); got != release || calls != 1 {
			t.Fatalf("reclamation must recheck actual free space once: admitted=%t calls=%d", got, calls)
		}
		if admission.reserved.Load() > 100 {
			t.Fatal("reclamation overcommitted the budget")
		}
		if release && (admission.streamStateReserved.Load() != 50 || admission.requestReserved.Load() != 50) {
			t.Fatal("reclamation changed an unrelated reservation class")
		}
	}
}

func TestMemoryPressureNeverQueuesCompetingReclamation(t *testing.T) {
	admission := &requestMemoryAdmission{budget: 100}
	admission.reserve(streamStateMemory, 100)
	entered, finish, done := make(chan struct{}), make(chan struct{}), make(chan bool, 1)
	var calls atomic.Int64
	admission.reclaim = func(needed int64) bool {
		calls.Add(1)
		close(entered)
		<-finish
		admission.release(streamStateMemory, needed)
		return true
	}
	go func() { done <- admission.reserve(requestLifetimeMemory, 50) }()
	<-entered
	if admission.reserve(requestLifetimeMemory, 50) {
		t.Fatal("competing pressure overcommitted memory")
	}
	close(finish)
	if !<-done || calls.Load() != 1 || admission.reserved.Load() != 100 {
		t.Fatal("pressure queued reclamation or lost accounting")
	}
}

func TestRequestMemoryRetentionTransfersUnderSaturation(t *testing.T) {
	for _, releaseFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "request finishes first", true: "retry finishes first"}[releaseFirst], func(t *testing.T) {
			admission := &requestMemoryAdmission{budget: minimumRequestWeightBytes}
			lease, ok := admission.acquire(0)
			if !ok {
				t.Fatal("admit")
			}
			if _, ok := admission.acquire(0); ok {
				t.Fatal("expected saturation")
			}
			for _, invalid := range []int{-1, 0, int(minimumRequestWeightBytes) + 1} {
				if _, ok := lease.retain(invalid); ok {
					t.Fatalf("retained invalid size %d", invalid)
				}
			}
			release, ok := lease.retain(50000)
			if !ok {
				t.Fatal("handoff tried to acquire more capacity")
			}
			if got := admission.reserved.Load(); got != minimumRequestWeightBytes {
				t.Fatalf("live work charge=%d", got)
			}
			if releaseFirst {
				release()
				if got := admission.reserved.Load(); got != minimumRequestWeightBytes {
					t.Fatalf("retry completion released live work: %d", got)
				}
				lease.release()
			} else {
				lease.release()
				if got := admission.reserved.Load(); got != 50000 {
					t.Fatalf("retained charge=%d", got)
				}
				if _, ok := lease.retain(1); ok {
					t.Fatal("retained from a released request")
				}
				release()
			}
			release()
			lease.release()
			if got := admission.reserved.Load(); got != 0 {
				t.Fatalf("reservation leak=%d", got)
			}
		})
	}
	admission := &requestMemoryAdmission{budget: minimumRequestWeightBytes}
	lease, _ := admission.acquire(0)
	release, _ := lease.retain(50000)
	var group sync.WaitGroup
	for range 20 {
		group.Go(lease.release)
		group.Go(release)
	}
	group.Wait()
	if got := admission.reserved.Load(); got != 0 {
		t.Fatalf("concurrent release left %d bytes", got)
	}
}

func TestRequestMemoryAdmissionUsesBoundedWeightedCapacity(t *testing.T) {
	admission := &requestMemoryAdmission{}
	lease, ok := admission.acquire(16 * 1024 * 1024)
	if !ok || lease == nil {
		t.Fatal("expected normal request to be admitted")
	}
	if got, want := admission.reserved.Load(), int64(80*1024*1024); got != want {
		t.Fatalf("reserved bytes = %d, want %d", got, want)
	}
	if got, want := admission.requestReserved.Load(), admission.reserved.Load(); got != want {
		t.Fatalf("request reservation = %d, want %d", got, want)
	}
	lease.release()
	lease.release()
	if got := admission.reserved.Load(); got != 0 {
		t.Fatalf("release must be idempotent, reserved = %d", got)
	}

	if lease, ok := admission.acquire(int(requestMemoryBudgetBytes)); ok || lease != nil {
		t.Fatal("expected an individually oversized weighted request to be rejected")
	}
	if got := admission.requestFailures.Load(); got != 1 {
		t.Fatalf("request reservation failures = %d, want 1", got)
	}
}

func TestRequestMemoryLeaseCanShrinkBeforeTransfer(t *testing.T) {
	admission := &requestMemoryAdmission{}
	lease, ok := admission.acquire(128 * 1024 * 1024)
	if !ok {
		t.Fatal("expected maximum request reservation")
	}
	if !lease.resize(2 * 1024 * 1024) {
		t.Fatal("expected reservation to shrink")
	}
	if got, want := admission.reserved.Load(), int64(10*1024*1024); got != want {
		t.Fatalf("resized bytes = %d, want %d", got, want)
	}
	lease.release()
	if got := admission.reserved.Load(); got != 0 {
		t.Fatalf("resized lease release left %d bytes", got)
	}
}

func TestRequestMemoryLeaseAccountsStreamPayloadOnce(t *testing.T) {
	admission := &requestMemoryAdmission{}
	const streamBytes = 16
	streamWeight := int64(streamBytes)
	admission.reserved.Store(requestMemoryBudgetBytes - streamWeight)
	lease := admission.newLease(streamStateMemory)
	if !lease.grow(streamBytes) {
		t.Fatal("expected stream bytes up to the aggregate budget to be admitted")
	}
	if lease.grow(1) {
		t.Fatal("expected stream bytes above the aggregate budget to be rejected")
	}
	lease.release()
	lease.release()
	if got, want := admission.reserved.Load(), requestMemoryBudgetBytes-streamWeight; got != want {
		t.Fatalf("stream lease release left %d bytes, want %d", got, want)
	}
	if got := admission.streamStateFailures.Load(); got != 1 {
		t.Fatalf("stream reservation failures = %d, want 1", got)
	}
}

func TestRequestMemoryBudgetScalesDownWithGoLimit(t *testing.T) {
	if got := requestMemoryBudgetForGoLimit(0); got != 1 {
		t.Fatalf("zero-limit payload budget = %d, want 1", got)
	}
	if got, want := requestMemoryBudgetForGoLimit(5*1024*1024*1024), int64(5*1024*1024*1024); got != want {
		t.Fatalf("reduced payload budget = %d, want %d", got, want)
	}
	if got, want := requestMemoryBudgetForGoLimit(DefaultGoMemoryLimitBytes-1), requestMemoryBudgetBytes-1; got != want {
		t.Fatalf("near-default payload budget = %d, want %d", got, want)
	}
	if got := requestMemoryBudgetForGoLimit(DefaultGoMemoryLimitBytes * 2); got != requestMemoryBudgetBytes {
		t.Fatalf("payload budget grew past guest cap: %d", got)
	}
}

func TestRequestMemoryAdmissionReportsOnlyActualSaturation(t *testing.T) {
	admission := &requestMemoryAdmission{}
	admission.reserved.Store(requestMemoryBudgetBytes - minimumRequestWeightBytes)
	if admission.saturated() {
		t.Fatal("one minimum request still fits")
	}
	admission.reserved.Add(1)
	if !admission.saturated() {
		t.Fatal("admission must be saturated when a minimum request cannot fit")
	}
}

func TestRequestMemoryDiagnosticsSeparateReservationClasses(t *testing.T) {
	admission := &requestMemoryAdmission{budget: 2 * minimumRequestWeightBytes}
	request, ok := admission.acquire(1)
	if !ok {
		t.Fatal("expected request reservation")
	}
	stream := admission.newLease(streamStateMemory)
	delivery := admission.newLease(downstreamDeliveryMemory)
	if !stream.grow(10) || !delivery.grow(20) {
		t.Fatal("expected stream reservations")
	}
	if rejected, ok := admission.acquire(1); ok || rejected != nil {
		t.Fatal("expected second minimum request to exceed remaining capacity")
	}

	diagnostics := admission.diagnostics()
	if diagnostics.RequestReservedBytes != minimumRequestWeightBytes ||
		diagnostics.StreamStateReservedBytes != 10 ||
		diagnostics.DownstreamReservedBytes != 20 ||
		diagnostics.ReservedBytes != minimumRequestWeightBytes+30 {
		t.Fatalf("unexpected memory diagnostics: %#v", diagnostics)
	}
	if diagnostics.PeakReservedBytes != diagnostics.ReservedBytes ||
		diagnostics.RequestReservationFailures != 1 ||
		!diagnostics.Saturated {
		t.Fatalf("unexpected capacity diagnostics: %#v", diagnostics)
	}

	request.release()
	stream.release()
	delivery.release()
	if got := admission.reserved.Load(); got != 0 {
		t.Fatalf("reservation release left %d bytes", got)
	}
}
