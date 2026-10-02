package billing

import "time"

// A local overload response is distinct from a saved request/concurrency quota.
// RetryAfter also survives public error wrapping and encrypted HTTP responses.
type retryAfterError struct {
	delay time.Duration
}

func (e *retryAfterError) Error() string             { return ErrAbuseRateLimit.Error() }
func (e *retryAfterError) Unwrap() error             { return ErrAbuseRateLimit }
func (e *retryAfterError) StatusCode() int           { return 429 }
func (e *retryAfterError) RetryAfter() time.Duration { return e.delay }

// RecordCallerFailure accepts only locally verified identities. Failed work,
// including dependency failures, consumes the same brief retry backoff.
// Cancellation and rejected retries do not extend a cooldown.
func (s *Service) RecordCallerFailure(claims *APIKeyClaims, dashboard *DashboardCredential, status int, code string) {
	if s == nil || status < 400 || status == 408 || status == 499 || code == ErrAbuseRateLimit.Code {
		return
	}
	now := time.Now()
	if claims != nil && claims.KeyID != "" && claims.OrganizationID != "" {
		s.rejections.record("key:"+claims.KeyID, now)
		s.rejections.record("org:"+claims.OrganizationID, now)
	}
	if dashboard != nil {
		s.rejections.record(dashboardAdmissionKey(dashboard), now)
	}
}

func (s *Service) callerBackoff(claims *APIKeyClaims, dashboard *DashboardCredential, now time.Time) error {
	var delay time.Duration
	if claims != nil {
		keyDelay := s.rejections.get("key:"+claims.KeyID, now)
		orgDelay := s.rejections.get("org:"+claims.OrganizationID, now)
		delay = max(keyDelay, orgDelay)
	}
	if dashboard != nil {
		actorDelay := s.rejections.get(dashboardAdmissionKey(dashboard), now)
		delay = max(delay, actorDelay)
	}
	if delay > 0 {
		return &retryAfterError{delay: delay}
	}
	return nil
}

func (s *Service) recordRequestSuccess(keyID, organizationID, dashboardIdentity string, started time.Time) {
	s.rejections.succeeded("key:"+keyID, started)
	s.rejections.succeeded("org:"+organizationID, started)
	if dashboardIdentity != "" {
		s.rejections.succeeded(dashboardIdentity, started)
	}
}

// A successful hold is not a successful request: clearing here would let
// repeated provider failures erase their own backoff before each dispatch.
func (s *Service) recordRequestOutcome(authorization *Authorization, event RequestEvent) {
	if event.Cancelled {
		return
	}
	if event.Error == nil && len(event.ProviderAttempts) > 0 && event.ProviderAttempts[len(event.ProviderAttempts)-1].Status == "success" {
		s.recordRequestSuccess(authorization.KeyID, authorization.OrganizationID, authorization.dashboardAdmissionIdentity, authorization.admissionStartedAt)
		return
	}
	now := time.Now()
	if authorization.KeyID != "" && authorization.OrganizationID != "" {
		s.rejections.record("key:"+authorization.KeyID, now)
		s.rejections.record("org:"+authorization.OrganizationID, now)
	}
	if authorization.dashboardAdmissionIdentity != "" {
		s.rejections.record(authorization.dashboardAdmissionIdentity, now)
	}
}
