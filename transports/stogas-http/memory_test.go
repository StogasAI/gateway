package stogashttp

import "testing"

func TestRequestMemoryAdmissionUsesBoundedWeightedCapacity(t *testing.T) {
	admission := &requestMemoryAdmission{}
	lease, ok := admission.acquire(16 * 1024 * 1024)
	if !ok || lease == nil {
		t.Fatal("expected normal request to be admitted")
	}
	if got, want := admission.used.Load(), int64(80*1024*1024); got != want {
		t.Fatalf("reserved bytes = %d, want %d", got, want)
	}
	lease.release()
	lease.release()
	if got := admission.used.Load(); got != 0 {
		t.Fatalf("release must be idempotent, used = %d", got)
	}

	if lease, ok := admission.acquire(int(requestMemoryBudgetBytes)); ok || lease != nil {
		t.Fatal("expected an individually oversized weighted request to be rejected")
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
	if got, want := admission.used.Load(), int64(10*1024*1024); got != want {
		t.Fatalf("resized bytes = %d, want %d", got, want)
	}
	lease.release()
	if got := admission.used.Load(); got != 0 {
		t.Fatalf("resized lease release left %d bytes", got)
	}
}

func TestRequestMemoryAdmissionReportsPressure(t *testing.T) {
	admission := &requestMemoryAdmission{}
	admission.used.Store(requestMemoryBudgetBytes*9/10 - 1)
	if admission.pressured() {
		t.Fatal("pressure must remain false below threshold")
	}
	admission.used.Store(requestMemoryBudgetBytes * 9 / 10)
	if !admission.pressured() {
		t.Fatal("pressure must become true at threshold")
	}
}
