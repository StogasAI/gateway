package stogashttp

import "testing"

func TestRequestMemoryAdmissionUsesBoundedWeightedCapacity(t *testing.T) {
	admission := &requestMemoryAdmission{}
	release, ok := admission.acquire(16 * 1024 * 1024)
	if !ok || release == nil {
		t.Fatal("expected normal request to be admitted")
	}
	if got, want := admission.used.Load(), int64(80*1024*1024); got != want {
		t.Fatalf("reserved bytes = %d, want %d", got, want)
	}
	release()
	release()
	if got := admission.used.Load(); got != 0 {
		t.Fatalf("release must be idempotent, used = %d", got)
	}

	if release, ok := admission.acquire(int(requestMemoryBudgetBytes)); ok || release != nil {
		t.Fatal("expected an individually oversized weighted request to be rejected")
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
