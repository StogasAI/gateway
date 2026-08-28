package stogashttp

import "testing"

func TestRequestMemoryAdmissionUsesBoundedWeightedCapacity(t *testing.T) {
	admission := &requestMemoryAdmission{}
	lease, ok := admission.acquire(16 * 1024 * 1024)
	if !ok || lease == nil {
		t.Fatal("expected normal request to be admitted")
	}
	if got, want := admission.reserved.Load(), int64(80*1024*1024); got != want {
		t.Fatalf("reserved bytes = %d, want %d", got, want)
	}
	if got, want := admission.requestBodyReserved.Load(), admission.reserved.Load(); got != want {
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
	if got := admission.requestBodyFailures.Load(); got != 1 {
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

func TestDefaultResourceProfileMatchesMeasuredGuest(t *testing.T) {
	if got, want := DefaultGuestMemoryBytes, int64(16*1024*1024*1024); got != want {
		t.Fatalf("guest memory = %d, want %d", got, want)
	}
	if got, want := DefaultGoMemoryLimitBytes, int64(10*1024*1024*1024); got != want {
		t.Fatalf("Go memory limit = %d, want %d", got, want)
	}
	if got, want := requestMemoryBudgetBytes, int64(4*1024*1024*1024); got != want {
		t.Fatalf("payload budget = %d, want %d", got, want)
	}
	if DefaultGuestVCPUCount != 4 || serverConcurrency != 2048 || readinessConcurrency != 64 {
		t.Fatalf("resource profile = %d vCPUs, %d public connections, and %d readiness connections; want 4, 2048, and 64", DefaultGuestVCPUCount, serverConcurrency, readinessConcurrency)
	}
}

func TestRequestMemoryBudgetScalesDownWithGoLimit(t *testing.T) {
	if got := requestMemoryBudgetForGoLimit(0); got != 1 {
		t.Fatalf("zero-limit payload budget = %d, want 1", got)
	}
	if got, want := requestMemoryBudgetForGoLimit(5*1024*1024*1024), int64(2*1024*1024*1024); got != want {
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
	if diagnostics.RequestBodyReservedBytes != minimumRequestWeightBytes ||
		diagnostics.StreamStateReservedBytes != 10 ||
		diagnostics.DownstreamReservedBytes != 20 ||
		diagnostics.ReservedBytes != minimumRequestWeightBytes+30 {
		t.Fatalf("unexpected memory diagnostics: %#v", diagnostics)
	}
	if diagnostics.PeakReservedBytes != diagnostics.ReservedBytes ||
		diagnostics.RequestBodyReservationFailures != 1 ||
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
