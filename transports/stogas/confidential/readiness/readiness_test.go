package readiness

import "testing"

func readyState() State {
	return State{
		BundleAcceptsActiveCert:    true,
		BundleContainsNode:         true,
		BundleLatestVerified:       true,
		CertificateReady:           true,
		CertificateSafe:            true,
		EntropyReady:               true,
		IdentityReady:              true,
		QuoteForwardSafe:           true,
		QuoteReady:                 true,
		RuntimeDependenciesHealthy: true,
		SecretsReady:               true,
		Serving:                    true,
	}
}

func TestEvaluateReadyOnlyWhenEveryGatePasses(t *testing.T) {
	result := Evaluate(readyState())
	if !result.Ready {
		t.Fatalf("expected ready, got reasons: %v", result.Reasons)
	}
	if len(result.Reasons) != 0 {
		t.Fatalf("expected no reasons, got %v", result.Reasons)
	}
}

func TestEvaluateFailsClosedBeforeBootPrerequisites(t *testing.T) {
	state := readyState()
	state.EntropyReady = false
	state.IdentityReady = false
	state.CertificateReady = false
	state.SecretsReady = false
	result := Evaluate(state)
	if result.Ready {
		t.Fatal("expected not ready")
	}
	assertReasons(t, result.Reasons,
		"entropy is not ready",
		"identity is not ready",
		"certificate is not ready",
		"secrets are not ready",
	)
}

func TestEvaluateFailsClosedWhenQuoteIsMissingOrNotForwardSafe(t *testing.T) {
	state := readyState()
	state.QuoteReady = false
	state.QuoteForwardSafe = false
	result := Evaluate(state)
	if result.Ready {
		t.Fatal("expected not ready")
	}
	assertReasons(t, result.Reasons, "quote is not ready", "quote is not forward-safe")
}

func TestEvaluateFailsClosedUntilLatestBundleContainsCurrentCertState(t *testing.T) {
	state := readyState()
	state.BundleLatestVerified = false
	state.BundleContainsNode = false
	state.BundleAcceptsActiveCert = false
	result := Evaluate(state)
	if result.Ready {
		t.Fatal("expected not ready")
	}
	assertReasons(t, result.Reasons,
		"latest bundle is not verified",
		"node is not in latest bundle",
		"latest bundle does not accept active certificate",
	)
}

func TestEvaluateFailsClosedForUnsafeCertificate(t *testing.T) {
	state := readyState()
	state.CertificateSafe = false
	result := Evaluate(state)
	if result.Ready {
		t.Fatal("expected not ready")
	}
	assertReasons(t, result.Reasons, "certificate is not safe")
}

func TestEvaluateFailsClosedForPlannedDrainOrStoppedServing(t *testing.T) {
	state := readyState()
	state.Draining = true
	state.Serving = false
	result := Evaluate(state)
	if result.Ready {
		t.Fatal("expected not ready")
	}
	assertReasons(t, result.Reasons, "node is not serving", "node is draining")
}

func TestEvaluateFailsClosedForRuntimeDependencyFailure(t *testing.T) {
	state := readyState()
	state.RuntimeDependenciesHealthy = false
	result := Evaluate(state)
	if result.Ready {
		t.Fatal("expected not ready")
	}
	assertReasons(t, result.Reasons, "runtime dependencies are unhealthy")
}

func TestEvaluateReasonOrderIsStableForHealthProbesAndDiagnostics(t *testing.T) {
	result := Evaluate(State{})
	if result.Ready {
		t.Fatal("expected not ready")
	}
	assertReasons(t, result.Reasons,
		"node is not serving",
		"entropy is not ready",
		"identity is not ready",
		"certificate is not ready",
		"certificate is not safe",
		"secrets are not ready",
		"quote is not ready",
		"quote is not forward-safe",
		"latest bundle is not verified",
		"node is not in latest bundle",
		"latest bundle does not accept active certificate",
		"runtime dependencies are unhealthy",
	)
}

func assertReasons(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("expected reasons %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected reasons %v, got %v", want, got)
		}
	}
}
