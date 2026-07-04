package readiness

type State struct {
	BundleAcceptsActiveCert    bool
	BundleContainsNode         bool
	BundleLatestVerified       bool
	CertificateReady           bool
	CertificateSafe            bool
	Draining                   bool
	EntropyReady               bool
	IdentityReady              bool
	QuoteForwardSafe           bool
	QuoteReady                 bool
	RuntimeDependenciesHealthy bool
	SecretsReady               bool
	Serving                    bool
}

type Result struct {
	Ready   bool
	Reasons []string
}

func Evaluate(state State) Result {
	reasons := make([]string, 0, 12)
	if !state.Serving {
		reasons = append(reasons, "node is not serving")
	}
	if state.Draining {
		reasons = append(reasons, "node is draining")
	}
	if !state.EntropyReady {
		reasons = append(reasons, "entropy is not ready")
	}
	if !state.IdentityReady {
		reasons = append(reasons, "identity is not ready")
	}
	if !state.CertificateReady {
		reasons = append(reasons, "certificate is not ready")
	}
	if !state.CertificateSafe {
		reasons = append(reasons, "certificate is not safe")
	}
	if !state.SecretsReady {
		reasons = append(reasons, "secrets are not ready")
	}
	if !state.QuoteReady {
		reasons = append(reasons, "quote is not ready")
	}
	if !state.QuoteForwardSafe {
		reasons = append(reasons, "quote is not forward-safe")
	}
	if !state.BundleLatestVerified {
		reasons = append(reasons, "latest bundle is not verified")
	}
	if !state.BundleContainsNode {
		reasons = append(reasons, "node is not in latest bundle")
	}
	if !state.BundleAcceptsActiveCert {
		reasons = append(reasons, "latest bundle does not accept active certificate")
	}
	if !state.RuntimeDependenciesHealthy {
		reasons = append(reasons, "runtime dependencies are unhealthy")
	}
	return Result{Ready: len(reasons) == 0, Reasons: reasons}
}
