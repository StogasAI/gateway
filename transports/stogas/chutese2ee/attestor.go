package chutese2ee

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"crypto/mlkem"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

type attestor struct {
	api          *apiClient
	diagnostics  *diagnostics
	policies     *policyCache
	collateral   *collateralGetter
	nras         *nrasVerifier
	trustedRoots *x509.CertPool
	cacheMu      sync.Mutex
	cache        map[string]verifiedInstance
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	lifecycleMu  sync.Mutex
	closing      bool
	refreshMu    sync.Mutex
	observed     map[string]map[string]observedAttestationInstance
	refresh      map[string]*attestationRefreshState
	flights      singleflight.Group
	refreshSlots chan struct{}
}

type observedAttestationInstance struct {
	Instance discoveredInstance
	LastSeen time.Time
}

type attestationRefreshState struct {
	Target        ModelTarget
	Failures      int
	InvalidatedAt time.Time
	NextAttempt   time.Time
	Refreshing    bool
}

const (
	maximumAttestationCacheEntries     = 1024
	maximumObservedInstancesPerChute   = 128
	maximumConcurrentEvidenceRefreshes = 3
)

func newAttestor(api *apiClient, diagnostics *diagnostics) (*attestor, error) {
	if api == nil || diagnostics == nil {
		return nil, ErrAttestationFailed
	}
	trustedRoots, err := loadIntelTrustedRoots()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := &attestor{
		api:          api,
		diagnostics:  diagnostics,
		policies:     &policyCache{api: api},
		collateral:   newCollateralGetter(),
		nras:         newNRASVerifier(),
		trustedRoots: trustedRoots,
		cache:        make(map[string]verifiedInstance),
		ctx:          ctx,
		cancel:       cancel,
		observed:     make(map[string]map[string]observedAttestationInstance),
		refresh:      make(map[string]*attestationRefreshState),
		refreshSlots: make(chan struct{}, maximumConcurrentEvidenceRefreshes),
	}
	result.wg.Add(1)
	go result.refreshLoop()
	return result, nil
}

func (a *attestor) close() {
	if a == nil {
		return
	}
	a.lifecycleMu.Lock()
	if a.closing {
		a.lifecycleMu.Unlock()
		return
	}
	a.closing = true
	a.lifecycleMu.Unlock()
	if a.cancel != nil {
		a.cancel()
	}
	a.wg.Wait()
	if a.collateral != nil {
		a.collateral.close()
	}
	if a.nras != nil {
		a.nras.close()
	}
	a.refreshMu.Lock()
	a.observed = nil
	a.refresh = nil
	a.refreshMu.Unlock()
	a.cacheMu.Lock()
	a.cache = nil
	a.cacheMu.Unlock()
}

func (a *attestor) verify(
	ctx context.Context,
	target ModelTarget,
	discovered []discoveredInstance,
	forceRefresh bool,
) (*attestationResult, error) {
	if a == nil || a.api == nil || a.diagnostics == nil {
		return nil, ErrAttestationFailed
	}
	key := attestationFlightKey(target, discovered)
	value, err, _ := a.flights.Do(key, func() (any, error) {
		started := time.Now()
		result, verifyErr := a.verifyOnce(ctx, target, discovered, forceRefresh)
		a.recordRefreshResult(target, result, verifyErr, forceRefresh, started, time.Now())
		return result, verifyErr
	})
	if value == nil {
		return nil, err
	}
	return value.(*attestationResult), err
}

func (a *attestor) verifyFirst(
	ctx context.Context,
	target ModelTarget,
	discovered []discoveredInstance,
) (verifiedInstance, error) {
	for _, instance := range discovered {
		if verification, ok := a.cachedInstance(target, instance, time.Now()); ok {
			return verification, nil
		}
	}
	type outcome struct {
		result *attestationResult
		err    error
	}
	baseContext := a.ctx
	if baseContext == nil {
		baseContext = context.Background()
	}
	verifyContext, cancel := context.WithTimeout(baseContext, attestationTimeout)
	done := make(chan outcome, 1)
	a.lifecycleMu.Lock()
	if a.closing {
		a.lifecycleMu.Unlock()
		cancel()
		return verifiedInstance{}, ErrAttestationFailed
	}
	a.wg.Add(1)
	a.lifecycleMu.Unlock()
	go func() {
		defer a.wg.Done()
		defer cancel()
		result, err := a.verify(verifyContext, target, discovered, false)
		done <- outcome{result: result, err: err}
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	firstCached := func() (verifiedInstance, bool) {
		now := time.Now()
		for _, instance := range discovered {
			if verification, ok := a.cachedInstance(target, instance, now); ok {
				return verification, true
			}
		}
		return verifiedInstance{}, false
	}
	for {
		if verification, ok := firstCached(); ok {
			return verification, nil
		}
		select {
		case <-ctx.Done():
			return verifiedInstance{}, errors.Join(ErrAttestationFailed, ctx.Err())
		case completed := <-done:
			if verification, ok := firstCached(); ok {
				return verification, nil
			}
			if completed.err != nil {
				return verifiedInstance{}, completed.err
			}
			if completed.result != nil {
				for _, verification := range completed.result.Instances {
					return verification, nil
				}
			}
			return verifiedInstance{}, ErrAttestationFailed
		case <-ticker.C:
		}
	}
}

func (a *attestor) verifyOnce(
	ctx context.Context,
	target ModelTarget,
	discovered []discoveredInstance,
	forceRefresh bool,
) (*attestationResult, error) {
	if !validModelTarget(target) || len(discovered) == 0 || len(discovered) > maximumObservedInstancesPerChute {
		return nil, ErrAttestationFailed
	}
	chuteID := target.ChuteID
	discoveredByID := make(map[string]discoveredInstance, len(discovered))
	for _, instance := range discovered {
		if !canonicalUUID(instance.ID) || len(instance.PublicKey) == 0 {
			return nil, fmt.Errorf("%w: invalid discovered instance", ErrAttestationFailed)
		}
		keyBytes, err := base64.StdEncoding.Strict().DecodeString(instance.PublicKey)
		if err != nil || len(keyBytes) != mlkem.EncapsulationKeySize768 {
			return nil, fmt.Errorf("%w: invalid discovered instance key", ErrAttestationFailed)
		}
		if _, duplicate := discoveredByID[instance.ID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate discovered instance", ErrAttestationFailed)
		}
		discoveredByID[instance.ID] = instance
	}

	policy, err := a.policies.current(ctx)
	if err != nil {
		a.diagnostics.recordAttestationFailure(chuteID, "measurement_policy")
		return nil, err
	}
	cached := a.cachedInstances(target, discovered, policy.Digest, time.Now())
	result := &attestationResult{
		Instances:       cached,
		FailureCounts:   make(map[string]int),
		PolicyDigest:    policy.Digest,
		PolicyFetchedAt: policy.FetchedAt,
	}
	if !forceRefresh {
		for instanceID := range cached {
			delete(discoveredByID, instanceID)
		}
	}
	if len(discoveredByID) == 0 {
		result.Complete = true
		return result, nil
	}
	result.Attempted = true
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("generate attestation nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	path := evidencePathPrefix + url.PathEscape(chuteID) + "/evidence?nonce=" + nonce
	var response evidenceResponse
	var status int
	for attempt := 0; attempt < maximumSafeReadAttempts; attempt++ {
		response = evidenceResponse{}
		var latency time.Duration
		status, latency, err = a.api.requestJSON(ctx, http.MethodGet, path, nil, maxEvidenceBody, &response)
		a.diagnostics.recordEvidence(chuteID, status, latency, err)
		if err == nil || attempt+1 >= maximumSafeReadAttempts || !retryableChutesRead(err, false) {
			break
		}
		delay, ok := chutesReadRetryDelay(err, attempt, 5*time.Second)
		if !ok || !waitForChutesRetry(ctx, delay) {
			break
		}
	}
	if err != nil {
		return result, fmt.Errorf("fetch Chutes evidence: %w", err)
	}
	if len(response.Evidence) > 128 || len(response.FailedInstanceIDs) > 128 {
		return nil, fmt.Errorf("%w: evidence response is too large", ErrAttestationFailed)
	}
	evidenceByID := make(map[string]instanceEvidence, len(response.Evidence))
	for _, item := range response.Evidence {
		if !canonicalUUID(item.InstanceID) {
			return nil, fmt.Errorf("%w: invalid evidence instance", ErrAttestationFailed)
		}
		if _, duplicate := evidenceByID[item.InstanceID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate evidence instance", ErrAttestationFailed)
		}
		evidenceByID[item.InstanceID] = item
	}
	failed := make(map[string]struct{}, len(response.FailedInstanceIDs))
	for _, instanceID := range response.FailedInstanceIDs {
		if !canonicalUUID(instanceID) {
			return nil, fmt.Errorf("%w: invalid failed evidence instance", ErrAttestationFailed)
		}
		if _, duplicate := failed[instanceID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate failed evidence instance", ErrAttestationFailed)
		}
		if _, hasEvidence := evidenceByID[instanceID]; hasEvidence {
			return nil, fmt.Errorf("%w: contradictory evidence response", ErrAttestationFailed)
		}
		failed[instanceID] = struct{}{}
	}

	var resultMu sync.Mutex
	var firstFailure error
	freshCount := 0
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(3)
	for instanceID, instance := range discoveredByID {
		item, ok := evidenceByID[instanceID]
		if !ok {
			category := "evidence_missing"
			if _, explicitlyFailed := failed[instanceID]; explicitlyFailed {
				category = "evidence_unavailable"
			}
			resultMu.Lock()
			result.FailureCounts[category]++
			resultMu.Unlock()
			continue
		}
		group.Go(func() error {
			verifiedAt := time.Now()
			measurement, keyPossessionVerified, verifyErr := verifyTDXEvidence(
				groupContext,
				item,
				nonce,
				instance.PublicKey,
				policy,
				a.collateral,
				a.trustedRoots,
				verifiedAt,
			)
			category := "tdx"
			if verifyErr == nil {
				category = "gpu"
				if target.GPUCount > measurement.GPUCount {
					verifyErr = fmt.Errorf("%w: assigned GPU count exceeds the TEE host policy", ErrGPUAttestationFailed)
				}
			}
			if verifyErr == nil {
				binding := sha256.Sum256([]byte(nonce + instance.PublicKey))
				verifyErr = a.nras.verify(
					groupContext,
					item.GPUEvidence,
					hex.EncodeToString(binding[:]),
					target.GPUCount,
					measurement.ExpectedGPUs,
					verifiedAt,
				)
				category = "gpu"
			}
			resultMu.Lock()
			if verifyErr != nil {
				if errors.Is(verifyErr, ErrMeasurementPolicy) {
					category = "measurement_policy"
				}
				result.FailureCounts[category]++
				if firstFailure == nil {
					firstFailure = verifyErr
				}
				resultMu.Unlock()
				return nil
			}
			verification := verifiedInstance{
				InstanceID:            instanceID,
				PublicKey:             instance.PublicKey,
				GPUCount:              target.GPUCount,
				MeasurementDigest:     policy.Digest,
				MeasurementName:       measurement.Name,
				MeasurementVersion:    measurement.Version,
				KeyPossessionVerified: keyPossessionVerified,
				VerifiedAt:            verifiedAt,
				ValidUntil:            verifiedAt.Add(attestationLifetime),
			}
			result.Instances[instanceID] = verification
			freshCount++
			resultMu.Unlock()
			a.storeCachedInstances(target, map[string]verifiedInstance{instanceID: verification})
			return nil
		})
	}
	_ = group.Wait()
	result.Complete = freshCount == len(discoveredByID)
	a.storeCachedInstances(target, result.Instances)
	for category, count := range result.FailureCounts {
		for range count {
			a.diagnostics.recordAttestationFailure(chuteID, category)
		}
	}
	if !result.Complete {
		return result, errors.Join(ErrAttestationFailed, firstFailure)
	}
	return result, nil
}

func attestationFlightKey(target ModelTarget, discovered []discoveredInstance) string {
	bindings := make([]string, 0, len(discovered))
	for _, instance := range discovered {
		bindings = append(bindings, attestationCacheKey(target, instance.ID, instance.PublicKey))
	}
	sort.Strings(bindings)
	digest := sha256.New()
	for _, binding := range bindings {
		_, _ = digest.Write([]byte(binding))
		_, _ = digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func (a *attestor) observe(target ModelTarget, discovered []discoveredInstance) {
	if a == nil || !validModelTarget(target) || len(discovered) == 0 {
		return
	}
	chuteID := target.ChuteID
	now := time.Now()
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	if a.observed == nil || a.refresh == nil {
		return
	}
	instances := a.observed[chuteID]
	if instances == nil {
		instances = make(map[string]observedAttestationInstance)
		a.observed[chuteID] = instances
	}
	state := a.refresh[chuteID]
	if state == nil {
		state = &attestationRefreshState{Target: target, NextAttempt: now}
		a.refresh[chuteID] = state
	}
	if state.Target != target {
		state.Target = target
		state.InvalidatedAt = now
		state.NextAttempt = now
	}
	for _, instance := range discovered {
		prior, exists := instances[instance.ID]
		changed := !exists || prior.Instance.PublicKey != instance.PublicKey
		instances[instance.ID] = observedAttestationInstance{
			Instance: discoveredInstance{ID: instance.ID, PublicKey: instance.PublicKey},
			LastSeen: now,
		}
		if changed {
			state.InvalidatedAt = now
			state.NextAttempt = now
		}
	}
	for len(instances) > maximumObservedInstancesPerChute {
		oldestID := ""
		var oldest time.Time
		for instanceID, instance := range instances {
			if oldestID == "" || instance.LastSeen.Before(oldest) {
				oldestID = instanceID
				oldest = instance.LastSeen
			}
		}
		delete(instances, oldestID)
	}
}

func (a *attestor) refreshLoop() {
	defer a.wg.Done()
	ticker := time.NewTicker(attestationRefreshTick)
	defer ticker.Stop()
	var refreshes sync.WaitGroup
	defer refreshes.Wait()
	for {
		select {
		case <-a.ctx.Done():
			return
		case now := <-ticker.C:
			for _, batch := range a.dueRefreshes(now) {
				refreshes.Add(1)
				go func() {
					defer refreshes.Done()
					a.refreshObserved(batch.Target, batch.Instances)
				}()
			}
		}
	}
}

type attestationRefreshBatch struct {
	Target    ModelTarget
	Instances []discoveredInstance
}

func (a *attestor) dueRefreshes(now time.Time) map[string]attestationRefreshBatch {
	result := make(map[string]attestationRefreshBatch)
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	for chuteID, instances := range a.observed {
		for instanceID, instance := range instances {
			if now.Sub(instance.LastSeen) >= attestationObservationTTL {
				delete(instances, instanceID)
			}
		}
		if len(instances) == 0 {
			delete(a.observed, chuteID)
			delete(a.refresh, chuteID)
			continue
		}
		state := a.refresh[chuteID]
		if state == nil {
			continue
		}
		if !validModelTarget(state.Target) || state.Refreshing || now.Before(state.NextAttempt) {
			continue
		}
		state.Refreshing = true
		batch := attestationRefreshBatch{Target: state.Target}
		for _, instance := range instances {
			batch.Instances = append(batch.Instances, instance.Instance)
		}
		sort.Slice(batch.Instances, func(left, right int) bool {
			return batch.Instances[left].ID < batch.Instances[right].ID
		})
		result[chuteID] = batch
	}
	return result
}

func (a *attestor) refreshObserved(target ModelTarget, discovered []discoveredInstance) {
	chuteID := target.ChuteID
	defer func() {
		a.refreshMu.Lock()
		if state := a.refresh[chuteID]; state != nil {
			state.Refreshing = false
		}
		a.refreshMu.Unlock()
	}()
	select {
	case a.refreshSlots <- struct{}{}:
		defer func() { <-a.refreshSlots }()
	case <-a.ctx.Done():
		return
	}
	ctx, cancel := context.WithTimeout(a.ctx, attestationTimeout)
	_, _ = a.verify(ctx, target, discovered, true)
	cancel()
}

func (a *attestor) recordRefreshResult(
	target ModelTarget,
	result *attestationResult,
	err error,
	forceRefresh bool,
	started time.Time,
	now time.Time,
) {
	chuteID := target.ChuteID
	attempted := forceRefresh || (result != nil && result.Attempted)
	if !attempted {
		return
	}
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	if a.refresh == nil {
		return
	}
	state := a.refresh[chuteID]
	if state == nil {
		state = &attestationRefreshState{Target: target}
		a.refresh[chuteID] = state
	}
	if err == nil && result != nil && result.Complete {
		state.Failures = 0
		if !state.InvalidatedAt.After(started) {
			state.NextAttempt = now.Add(attestationRefreshInterval + randomAttestationRefreshJitter())
		}
		return
	}
	state.Failures++
	delay := attestationRetryMinimum
	for attempt := 1; attempt < state.Failures && delay < attestationRetryMaximum; attempt++ {
		delay *= 2
	}
	if delay > attestationRetryMaximum {
		delay = attestationRetryMaximum
	}
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusTooManyRequests && statusErr.RetryAfter > delay {
		delay = statusErr.RetryAfter
		if delay > time.Minute {
			delay = time.Minute
		}
	}
	state.NextAttempt = now.Add(delay)
}

func randomAttestationRefreshJitter() time.Duration {
	maximum := int64(attestationRefreshJitter)
	if maximum <= 0 {
		return 0
	}
	value, err := rand.Int(rand.Reader, big.NewInt(maximum+1))
	if err != nil {
		return 0
	}
	return time.Duration(value.Int64())
}

func (a *attestor) cachedInstance(
	target ModelTarget,
	instance discoveredInstance,
	now time.Time,
) (verifiedInstance, bool) {
	if a == nil {
		return verifiedInstance{}, false
	}
	key := attestationCacheKey(target, instance.ID, instance.PublicKey)
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	verification, ok := a.cache[key]
	if !ok {
		return verifiedInstance{}, false
	}
	if !now.Before(verification.ValidUntil) || verification.InstanceID != instance.ID ||
		verification.PublicKey != instance.PublicKey || verification.GPUCount != target.GPUCount {
		delete(a.cache, key)
		return verifiedInstance{}, false
	}
	return verification, true
}

func (a *attestor) cachedInstances(
	target ModelTarget,
	discovered []discoveredInstance,
	policyDigest string,
	now time.Time,
) map[string]verifiedInstance {
	result := make(map[string]verifiedInstance)
	if a == nil {
		return result
	}
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	for key, verification := range a.cache {
		if !now.Before(verification.ValidUntil) || verification.MeasurementDigest != policyDigest {
			delete(a.cache, key)
		}
	}
	for _, instance := range discovered {
		verification, ok := a.cache[attestationCacheKey(target, instance.ID, instance.PublicKey)]
		if ok && verification.InstanceID == instance.ID && verification.PublicKey == instance.PublicKey && verification.GPUCount == target.GPUCount {
			result[instance.ID] = verification
		}
	}
	return result
}

func (a *attestor) storeCachedInstances(target ModelTarget, instances map[string]verifiedInstance) {
	if a == nil || len(instances) == 0 {
		return
	}
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	if a.cache == nil {
		return
	}
	for _, verification := range instances {
		if verification.GPUCount != target.GPUCount || target.GPUCount < 1 || target.GPUCount > 8 {
			continue
		}
		key := attestationCacheKey(target, verification.InstanceID, verification.PublicKey)
		if _, exists := a.cache[key]; !exists {
			for len(a.cache) >= maximumAttestationCacheEntries {
				oldestKey := ""
				var oldestExpiry time.Time
				for candidateKey, candidate := range a.cache {
					if oldestKey == "" || candidate.ValidUntil.Before(oldestExpiry) ||
						(candidate.ValidUntil.Equal(oldestExpiry) && candidateKey < oldestKey) {
						oldestKey = candidateKey
						oldestExpiry = candidate.ValidUntil
					}
				}
				delete(a.cache, oldestKey)
			}
		}
		a.cache[key] = verification
	}
}

func attestationCacheKey(target ModelTarget, instanceID, publicKey string) string {
	digest := sha256.Sum256([]byte(publicKey))
	return target.ChuteID + "\x00" + fmt.Sprintf("%d", target.GPUCount) + "\x00" + instanceID + "\x00" + string(digest[:])
}

func validModelTarget(target ModelTarget) bool {
	return canonicalUUID(target.ChuteID) && target.GPUCount >= 1 && target.GPUCount <= 8
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}
