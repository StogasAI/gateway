package chutese2ee

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"sync"
	"time"

	"crypto/mlkem"
	"golang.org/x/sync/singleflight"
)

var ticketPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)

const maximumSynchronousRefills = 2
const maximumTrackedTicketTakes = 512
const maximumSynchronousRefillBackoffWait = 2 * time.Second

type poolState struct {
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	pools       map[string]*ticketPool
	verified    map[string]map[string]verifiedInstance
	cooldowns   map[string]map[string]time.Time
	activity    map[string]*ticketActivity
	warming     map[string]bool
	refillState map[string]*ticketRefillState
	closing     bool
	refills     singleflight.Group
	api         *apiClient
	attestor    *attestor
	diagnostics *diagnostics
}

func newPoolState(api *apiClient, attestor *attestor, diagnostics *diagnostics) *poolState {
	ctx, cancel := context.WithCancel(context.Background())
	state := &poolState{
		ctx:         ctx,
		cancel:      cancel,
		pools:       make(map[string]*ticketPool),
		verified:    make(map[string]map[string]verifiedInstance),
		cooldowns:   make(map[string]map[string]time.Time),
		activity:    make(map[string]*ticketActivity),
		warming:     make(map[string]bool),
		refillState: make(map[string]*ticketRefillState),
		api:         api,
		attestor:    attestor,
		diagnostics: diagnostics,
	}
	state.wg.Add(1)
	go state.warmLoop()
	return state
}

func (s *poolState) reserve(target ModelTarget) (reservedTicket, error) {
	if !validModelTarget(target) {
		return reservedTicket{}, ErrMeasurementPolicy
	}
	if err := s.rememberTarget(target); err != nil {
		return reservedTicket{}, err
	}
	chuteID := target.ChuteID
	for attempt := 0; attempt < maximumSynchronousRefills; attempt++ {
		if ticket, ok := s.take(target, time.Now()); ok {
			s.diagnostics.recordTicketAvailable(chuteID)
			s.maybeWarm(target)
			return ticket, nil
		}
		_, err, _ := s.refills.Do(modelTargetKey(target), func() (any, error) {
			if s.hasUsable(target, time.Now()) {
				return nil, nil
			}
			return nil, s.refill(target)
		})
		if err != nil {
			if attempt+1 < maximumSynchronousRefills && retryableChutesRead(err, true) {
				if delay, ok := s.shortRefillBackoff(chuteID, time.Now()); ok &&
					waitForChutesRetry(s.ctx, delay) {
					continue
				}
			}
			s.diagnostics.recordTicketStarvation(chuteID)
			return reservedTicket{}, errors.Join(ErrNoUsableTicket, err)
		}
	}
	if ticket, ok := s.take(target, time.Now()); ok {
		s.diagnostics.recordTicketAvailable(chuteID)
		s.maybeWarm(target)
		return ticket, nil
	}
	s.diagnostics.recordTicketStarvation(chuteID)
	return reservedTicket{}, ErrNoUsableTicket
}

func (s *poolState) rememberTarget(target ModelTarget) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	activity := s.activity[target.ChuteID]
	if activity == nil {
		activity = &ticketActivity{}
		s.activity[target.ChuteID] = activity
	}
	if validModelTarget(activity.Target) && activity.Target != target {
		return fmt.Errorf("%w: conflicting Chutes deployment target", ErrMeasurementPolicy)
	}
	activity.Target = target
	return nil
}

func (s *poolState) shortRefillBackoff(chuteID string, now time.Time) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.refillState[chuteID]
	if state == nil || !now.Before(state.NotBefore) {
		return 0, false
	}
	delay := state.NotBefore.Sub(now)
	return delay, delay <= maximumSynchronousRefillBackoffWait
}

func (s *poolState) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	s.closing = true
	s.mu.Unlock()
	s.cancel()
	s.wg.Wait()
}

func (s *poolState) maybeWarm(target ModelTarget) {
	if s == nil || s.api == nil {
		return
	}
	chuteID := target.ChuteID
	now := time.Now()
	s.mu.Lock()
	s.syncVerifiedLocked(target, now)
	s.pruneLocked(chuteID, now)
	needsWarm := !s.closing && s.shouldWarmLocked(chuteID, now) && s.canRefillLocked(chuteID, now) &&
		!s.warming[chuteID] && s.ctx.Err() == nil
	if !needsWarm {
		s.mu.Unlock()
		return
	}
	s.warming[chuteID] = true
	s.wg.Add(1)
	s.mu.Unlock()

	go func() {
		defer s.wg.Done()
		defer func() {
			s.mu.Lock()
			delete(s.warming, chuteID)
			s.mu.Unlock()
		}()
		_, _, _ = s.refills.Do(modelTargetKey(target), func() (any, error) {
			return nil, s.refill(target)
		})
	}()
}

func (s *poolState) warmLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(ticketWarmCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			s.mu.Lock()
			targets := make([]ModelTarget, 0, len(s.activity))
			for chuteID, activity := range s.activity {
				if activity == nil || !validModelTarget(activity.Target) || now.Sub(activity.LastDemandAt) >= credentialIdleLifetime {
					delete(s.activity, chuteID)
					delete(s.refillState, chuteID)
					continue
				}
				targets = append(targets, activity.Target)
			}
			s.mu.Unlock()
			for _, target := range targets {
				s.maybeWarm(target)
			}
		}
	}
}

func (s *poolState) shouldWarmLocked(chuteID string, now time.Time) bool {
	activity := s.activity[chuteID]
	pool := s.pools[chuteID]
	if activity == nil || pool == nil || !activity.LastDemandAt.After(activity.LastRefillAt) {
		return false
	}
	remaining, nearestExpiry := s.usablePoolStateLocked(activity.Target, now)
	if remaining == 0 || (!nearestExpiry.IsZero() && nearestExpiry.Sub(now) <= warmExpiryThreshold) {
		return true
	}
	cutoff := now.Add(-ticketDemandWindow)
	first := 0
	for first < len(activity.Takes) && activity.Takes[first].Before(cutoff) {
		first++
	}
	if first > 0 {
		activity.Takes = append(activity.Takes[:0], activity.Takes[first:]...)
	}
	if len(activity.Takes) == 0 {
		return false
	}
	elapsed := now.Sub(activity.Takes[0])
	if elapsed < time.Second {
		elapsed = time.Second
	}
	headroom := int(
		(int64(len(activity.Takes))*int64(ticketRefillRunway)+int64(elapsed)-1)/
			int64(elapsed),
	) + 1
	if headroom < 2 {
		headroom = 2
	}
	if headroom > 50 {
		headroom = 50
	}
	return remaining <= headroom
}

func (s *poolState) canRefillLocked(chuteID string, now time.Time) bool {
	state := s.refillState[chuteID]
	return state == nil || !now.Before(state.NotBefore)
}

func (s *poolState) usablePoolStateLocked(target ModelTarget, now time.Time) (int, time.Time) {
	chuteID := target.ChuteID
	pool := s.pools[chuteID]
	verified := s.verified[chuteID]
	cooldowns := s.cooldowns[chuteID]
	remaining := 0
	var nearestExpiry time.Time
	for instanceID, tickets := range poolInstances(pool) {
		verification, ok := verified[instanceID]
		if tickets == nil || !ok || verification.PublicKey != tickets.PublicKey ||
			verification.GPUCount != target.GPUCount || !now.Before(verification.ValidUntil) || now.Before(cooldowns[instanceID]) {
			continue
		}
		remaining += len(tickets.Values)
		for _, ticket := range tickets.Values {
			if nearestExpiry.IsZero() || ticket.ExpiresAt.Before(nearestExpiry) {
				nearestExpiry = ticket.ExpiresAt
			}
		}
	}
	return remaining, nearestExpiry
}

func (s *poolState) hasUsable(target ModelTarget, now time.Time) bool {
	chuteID := target.ChuteID
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncVerifiedLocked(target, now)
	s.pruneLocked(chuteID, now)
	pool := s.pools[chuteID]
	for instanceID, tickets := range poolInstances(pool) {
		verification, ok := s.verified[chuteID][instanceID]
		if ok && verification.PublicKey == tickets.PublicKey && verification.GPUCount == target.GPUCount && now.Before(verification.ValidUntil) &&
			!now.Before(s.cooldowns[chuteID][instanceID]) && len(tickets.Values) > 0 {
			return true
		}
	}
	return false
}

func poolInstances(pool *ticketPool) map[string]*instanceTickets {
	if pool == nil {
		return nil
	}
	return pool.Instances
}

func (s *poolState) take(target ModelTarget, now time.Time) (reservedTicket, bool) {
	chuteID := target.ChuteID
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncVerifiedLocked(target, now)
	s.pruneLocked(chuteID, now)
	pool := s.pools[chuteID]
	if pool == nil || len(pool.Order) == 0 {
		return reservedTicket{}, false
	}
	verified := s.verified[chuteID]
	cooldowns := s.cooldowns[chuteID]
	for offset := 0; offset < len(pool.Order); offset++ {
		index := (pool.Cursor + offset) % len(pool.Order)
		instanceID := pool.Order[index]
		instanceTickets := pool.Instances[instanceID]
		verification, ok := verified[instanceID]
		if instanceTickets == nil || len(instanceTickets.Values) == 0 || !ok ||
			verification.PublicKey != instanceTickets.PublicKey || verification.GPUCount != target.GPUCount || !now.Before(verification.ValidUntil) ||
			now.Before(cooldowns[instanceID]) {
			continue
		}
		value := instanceTickets.Values[0]
		instanceTickets.Values = instanceTickets.Values[1:]
		pool.Cursor = (index + 1) % len(pool.Order)
		s.recordDemandLocked(target, now)
		return reservedTicket{
			ChuteID:    chuteID,
			InstanceID: instanceID,
			PublicKey:  instanceTickets.PublicKey,
			Value:      value.Value,
		}, true
	}
	return reservedTicket{}, false
}

func (s *poolState) recordDemandLocked(target ModelTarget, now time.Time) {
	chuteID := target.ChuteID
	activity := s.activity[chuteID]
	if activity == nil {
		activity = &ticketActivity{Target: target}
		s.activity[chuteID] = activity
	}
	activity.Target = target
	activity.LastDemandAt = now
	if len(activity.Takes) >= maximumTrackedTicketTakes {
		kept := len(activity.Takes) / 2
		copy(activity.Takes, activity.Takes[len(activity.Takes)-kept:])
		activity.Takes = activity.Takes[:kept]
	}
	activity.Takes = append(activity.Takes, now)
}

func (s *poolState) refill(target ModelTarget) (resultErr error) {
	if !validModelTarget(target) {
		return ErrMeasurementPolicy
	}
	if err := s.rememberTarget(target); err != nil {
		return err
	}
	chuteID := target.ChuteID
	now := time.Now()
	s.mu.Lock()
	if !s.canRefillLocked(chuteID, now) {
		state := s.refillState[chuteID]
		resultErr = &ticketRefillBackoffError{
			Cause:      state.LastError,
			RetryAfter: max(time.Millisecond, time.Until(state.NotBefore)),
		}
		s.mu.Unlock()
		return resultErr
	}
	s.mu.Unlock()
	defer func() { s.recordRefillResult(chuteID, resultErr) }()

	discovered, expiresAt, err := s.discover(target)
	if err != nil {
		return err
	}
	now = time.Now()
	usable := s.cachedVerified(target, discovered, now)
	if len(usable) == 0 {
		if verifyErr := s.attest(target, discovered, true); verifyErr != nil {
			return verifyErr
		}
		usable = s.cachedVerified(target, discovered, time.Now())
	}
	if len(usable) == 0 {
		return ErrAttestationFailed
	}
	if time.Until(expiresAt) < 10*time.Second {
		discovered, expiresAt, err = s.discover(target)
		if err != nil {
			return err
		}
		usable = s.cachedVerified(target, discovered, time.Now())
		if len(usable) == 0 {
			if verifyErr := s.attest(target, discovered, true); verifyErr != nil {
				return verifyErr
			}
			usable = s.cachedVerified(target, discovered, time.Now())
			if len(usable) == 0 {
				return ErrNoUsableTicket
			}
		}
	}
	s.install(target, discovered, expiresAt)
	return nil
}

func (s *poolState) recordRefillResult(chuteID string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.refillState, chuteID)
		return
	}
	if errors.Is(err, context.Canceled) && s.ctx.Err() != nil {
		return
	}
	state := s.refillState[chuteID]
	if state == nil {
		state = &ticketRefillState{}
		s.refillState[chuteID] = state
	}
	state.Failures++
	state.LastError = err
	delay := ticketRefillRetryMinimum
	for attempt := 1; attempt < state.Failures && delay < ticketRefillRetryMaximum; attempt++ {
		delay *= 2
	}
	if delay > ticketRefillRetryMaximum {
		delay = ticketRefillRetryMaximum
	}
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) {
		switch {
		case statusErr.StatusCode == http.StatusTooManyRequests && statusErr.RetryAfter > delay:
			delay = min(statusErr.RetryAfter, time.Minute)
		case statusErr.StatusCode >= 400 && statusErr.StatusCode < 500 &&
			statusErr.StatusCode != http.StatusRequestTimeout && statusErr.StatusCode != http.StatusTooEarly:
			delay = ticketRefillRetryMaximum
		}
	}
	state.NotBefore = time.Now().Add(delay)
}

func (s *poolState) attest(target ModelTarget, discovered []discoveredInstance, coldPath bool) error {
	if s.attestor == nil {
		return ErrAttestationFailed
	}
	chuteID := target.ChuteID
	started := time.Now()
	ctx, cancel := context.WithTimeout(s.ctx, attestationTimeout)
	verification, verifyErr := s.attestor.verifyFirst(ctx, target, discovered)
	cancel()
	if coldPath {
		s.diagnostics.recordColdPath(chuteID, time.Since(started), verifyErr)
	}
	if verifyErr == nil {
		s.mu.Lock()
		if s.verified[chuteID] == nil {
			s.verified[chuteID] = make(map[string]verifiedInstance)
		}
		s.verified[chuteID][verification.InstanceID] = verification
		s.mu.Unlock()
		return nil
	}
	return verifyErr
}

func (s *poolState) discover(target ModelTarget) ([]discoveredInstance, time.Time, error) {
	chuteID := target.ChuteID
	var instances []discoveredInstance
	var expiresAt time.Time
	err := retryChutesRead(s.ctx, true, 2*time.Second, func() error {
		var response discoveryResponse
		path := discoveryPathPrefix + url.PathEscape(chuteID)
		status, latency, requestErr := s.api.requestJSON(
			s.ctx,
			http.MethodGet,
			path,
			nil,
			maxDiscoveryBody,
			&response,
		)
		s.diagnostics.recordDiscovery(chuteID, status, latency, requestErr)
		if requestErr != nil {
			return requestErr
		}
		var validationErr error
		instances, expiresAt, validationErr = validateDiscovery(response, time.Now())
		return validationErr
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	if s.attestor != nil {
		s.attestor.observe(target, instances)
	}
	return instances, expiresAt, nil
}

func validateDiscovery(response discoveryResponse, now time.Time) ([]discoveredInstance, time.Time, error) {
	if len(response.Instances) == 0 || len(response.Instances) > maximumDiscoveredInstances || response.ExpiresIn < 1 || response.ExpiresIn > 75 {
		return nil, time.Time{}, errors.New("invalid Chutes discovery response")
	}
	expiresAt := time.Unix(response.ExpiresAtUnix, 0)
	byDuration := now.Add(time.Duration(response.ExpiresIn) * time.Second)
	if expiresAt.After(byDuration) {
		expiresAt = byDuration
	}
	if !expiresAt.After(now.Add(ticketExpiryMargin)) || expiresAt.After(now.Add(75*time.Second)) {
		return nil, time.Time{}, errors.New("invalid Chutes ticket expiry")
	}
	expiresAt = expiresAt.Add(-ticketExpiryMargin)
	instanceIDs := make(map[string]struct{}, len(response.Instances))
	tickets := make(map[string]struct{}, len(response.Instances)*10)
	for index := range response.Instances {
		instance := &response.Instances[index]
		if !canonicalUUID(instance.ID) || len(instance.Tickets) == 0 || len(instance.Tickets) > 10 {
			return nil, time.Time{}, errors.New("invalid Chutes discovery instance")
		}
		if _, duplicate := instanceIDs[instance.ID]; duplicate {
			return nil, time.Time{}, errors.New("duplicate Chutes discovery instance")
		}
		instanceIDs[instance.ID] = struct{}{}
		publicKey, err := base64.StdEncoding.Strict().DecodeString(instance.PublicKey)
		if err != nil || len(publicKey) != mlkem.EncapsulationKeySize768 {
			return nil, time.Time{}, errors.New("invalid Chutes discovery public key")
		}
		for _, ticket := range instance.Tickets {
			if !ticketPattern.MatchString(ticket) {
				return nil, time.Time{}, errors.New("invalid Chutes invocation ticket")
			}
			if _, duplicate := tickets[ticket]; duplicate {
				return nil, time.Time{}, errors.New("duplicate Chutes invocation ticket")
			}
			tickets[ticket] = struct{}{}
		}
	}
	return response.Instances, expiresAt, nil
}

func (s *poolState) cachedVerified(target ModelTarget, discovered []discoveredInstance, now time.Time) map[string]verifiedInstance {
	chuteID := target.ChuteID
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]verifiedInstance)
	verified := s.verified[chuteID]
	for _, instance := range discovered {
		verification, ok := verified[instance.ID]
		if s.attestor != nil {
			shared, sharedOK := s.attestor.cachedInstance(target, instance, now)
			if sharedOK {
				if verified == nil {
					verified = make(map[string]verifiedInstance)
					s.verified[chuteID] = verified
				}
				verification = shared
				verified[instance.ID] = shared
				ok = true
			}
		}
		if ok && verification.PublicKey == instance.PublicKey && verification.GPUCount == target.GPUCount && now.Before(verification.ValidUntil) {
			result[instance.ID] = verification
		}
	}
	return result
}

func (s *poolState) syncVerifiedLocked(target ModelTarget, now time.Time) {
	if s == nil || s.attestor == nil {
		return
	}
	chuteID := target.ChuteID
	pool := s.pools[chuteID]
	if pool == nil {
		return
	}
	verified := s.verified[chuteID]
	for instanceID, tickets := range pool.Instances {
		if tickets == nil {
			continue
		}
		verification, ok := s.attestor.cachedInstance(target, discoveredInstance{
			ID:        instanceID,
			PublicKey: tickets.PublicKey,
		}, now)
		if !ok {
			continue
		}
		if verified == nil {
			verified = make(map[string]verifiedInstance)
			s.verified[chuteID] = verified
		}
		verified[instanceID] = verification
	}
}

func (s *poolState) install(target ModelTarget, discovered []discoveredInstance, expiresAt time.Time) {
	chuteID := target.ChuteID
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(chuteID, now)
	pool := s.pools[chuteID]
	if pool == nil {
		pool = &ticketPool{Instances: make(map[string]*instanceTickets)}
		s.pools[chuteID] = pool
	}
	existingValues := make(map[string]struct{})
	for _, tickets := range pool.Instances {
		for _, ticket := range tickets.Values {
			existingValues[ticket.Value] = struct{}{}
		}
	}
	for _, instance := range discovered {
		tickets := pool.Instances[instance.ID]
		if tickets == nil || tickets.PublicKey != instance.PublicKey {
			tickets = &instanceTickets{PublicKey: instance.PublicKey}
			pool.Instances[instance.ID] = tickets
		}
		for _, value := range instance.Tickets {
			if _, exists := existingValues[value]; exists {
				continue
			}
			tickets.Values = append(tickets.Values, pooledTicket{Value: value, ExpiresAt: expiresAt})
			existingValues[value] = struct{}{}
		}
	}
	s.rebuildOrderLocked(pool)
	activity := s.activity[chuteID]
	if activity == nil {
		activity = &ticketActivity{Target: target}
		s.activity[chuteID] = activity
	}
	activity.Target = target
	activity.LastRefillAt = now
}

func (s *poolState) observeInvoke(ticket reservedTicket, status int, retryAfter time.Duration, err error) {
	s.diagnostics.recordInvoke(ticket.ChuteID, status, err)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cooldowns[ticket.ChuteID] == nil {
		s.cooldowns[ticket.ChuteID] = make(map[string]time.Time)
	}
	switch {
	case err != nil:
		s.clearInstanceTicketsLocked(ticket.ChuteID, ticket.InstanceID)
		s.cooldowns[ticket.ChuteID][ticket.InstanceID] = now.Add(instanceCooldown)
	case status == 404 || status == 410:
		s.clearInstanceTicketsLocked(ticket.ChuteID, ticket.InstanceID)
		delete(s.verified[ticket.ChuteID], ticket.InstanceID)
		s.cooldowns[ticket.ChuteID][ticket.InstanceID] = now.Add(30 * time.Second)
	case status == 403:
		delete(s.pools, ticket.ChuteID)
	case status == 429 || status == 500 || status == 502 || status == 503 || status == 504:
		if retryAfter <= 0 {
			retryAfter = instanceCooldown
		}
		if retryAfter > 30*time.Second {
			retryAfter = 30 * time.Second
		}
		s.cooldowns[ticket.ChuteID][ticket.InstanceID] = now.Add(retryAfter)
	}
}

func (s *poolState) clearInstanceTicketsLocked(chuteID, instanceID string) {
	if pool := s.pools[chuteID]; pool != nil {
		delete(pool.Instances, instanceID)
		s.rebuildOrderLocked(pool)
	}
}

func (s *poolState) pruneLocked(chuteID string, now time.Time) {
	if pool := s.pools[chuteID]; pool != nil {
		for instanceID, tickets := range pool.Instances {
			if tickets == nil {
				delete(pool.Instances, instanceID)
				continue
			}
			kept := tickets.Values[:0]
			for _, ticket := range tickets.Values {
				if now.Before(ticket.ExpiresAt) {
					kept = append(kept, ticket)
				}
			}
			tickets.Values = kept
			if len(tickets.Values) == 0 {
				delete(pool.Instances, instanceID)
			}
		}
		if len(pool.Instances) == 0 {
			delete(s.pools, chuteID)
		} else {
			s.rebuildOrderLocked(pool)
		}
	}
	for instanceID, verification := range s.verified[chuteID] {
		if !now.Before(verification.ValidUntil) {
			delete(s.verified[chuteID], instanceID)
		}
	}
	for instanceID, until := range s.cooldowns[chuteID] {
		if !now.Before(until) {
			delete(s.cooldowns[chuteID], instanceID)
		}
	}
}

func (s *poolState) rebuildOrderLocked(pool *ticketPool) {
	if pool == nil {
		return
	}
	pool.Order = pool.Order[:0]
	for instanceID := range pool.Instances {
		pool.Order = append(pool.Order, instanceID)
	}
	sort.Strings(pool.Order)
	if len(pool.Order) == 0 {
		pool.Cursor = 0
	} else {
		pool.Cursor %= len(pool.Order)
	}
}

func (s *poolState) health() map[string]poolHealth {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	chuteIDs := make(map[string]struct{})
	for chuteID := range s.pools {
		chuteIDs[chuteID] = struct{}{}
	}
	for chuteID := range s.verified {
		chuteIDs[chuteID] = struct{}{}
	}
	for chuteID := range s.refillState {
		chuteIDs[chuteID] = struct{}{}
	}
	result := make(map[string]poolHealth, len(chuteIDs))
	for chuteID := range chuteIDs {
		activity := s.activity[chuteID]
		target := ModelTarget{}
		if activity != nil {
			target = activity.Target
		}
		if validModelTarget(target) {
			s.syncVerifiedLocked(target, now)
		}
		s.pruneLocked(chuteID, now)
		state := poolHealth{
			CredentialPools:       1,
			verifiedBindings:      make(map[string]struct{}),
			keyPossessionBindings: make(map[string]struct{}),
			cooldownInstanceIDs:   make(map[string]struct{}),
		}
		if refill := s.refillState[chuteID]; refill != nil && now.Before(refill.NotBefore) {
			remaining := refill.NotBefore.Sub(now)
			state.RefillBackoffSeconds = max(1, int64((remaining+time.Second-1)/time.Second))
			state.CredentialPoolsInRefillBackoff = 1
		}
		digests := map[string]struct{}{}
		versions := map[string]struct{}{}
		for instanceID, verification := range s.verified[chuteID] {
			binding := instanceID + "\x00" + verification.PublicKey
			state.verifiedBindings[binding] = struct{}{}
			if verification.KeyPossessionVerified {
				state.keyPossessionBindings[binding] = struct{}{}
			}
			age := int64(now.Sub(verification.VerifiedAt).Seconds())
			if age > state.OldestVerificationAgeSeconds {
				state.OldestVerificationAgeSeconds = age
			}
			digests[verification.MeasurementDigest] = struct{}{}
			versions[verification.MeasurementName+"@"+verification.MeasurementVersion] = struct{}{}
		}
		if s.pools[chuteID] != nil {
			var nearestExpiry time.Time
			if validModelTarget(target) {
				state.UsableTickets, nearestExpiry = s.usablePoolStateLocked(target, now)
			}
			if state.UsableTickets > 0 && !nearestExpiry.IsZero() {
				state.NearestTicketExpirySeconds = max(0, int64(nearestExpiry.Sub(now).Seconds()))
			}
		}
		for instanceID, until := range s.cooldowns[chuteID] {
			if now.Before(until) {
				state.cooldownInstanceIDs[instanceID] = struct{}{}
			}
		}
		state.VerifiedInstances = len(state.verifiedBindings)
		state.KeyPossessionVerifiedInstances = len(state.keyPossessionBindings)
		state.CooldownInstances = len(state.cooldownInstanceIDs)
		for digest := range digests {
			state.MeasurementDigests = append(state.MeasurementDigests, digest)
		}
		for version := range versions {
			state.MeasurementVersions = append(state.MeasurementVersions, version)
		}
		sort.Strings(state.MeasurementDigests)
		sort.Strings(state.MeasurementVersions)
		result[chuteID] = state
	}
	return result
}

func aggregatePoolHealth(states []*poolState) map[string]poolHealth {
	result := make(map[string]poolHealth)
	for _, pools := range states {
		if pools == nil {
			continue
		}
		for chuteID, source := range pools.health() {
			target := result[chuteID]
			target.CredentialPools += source.CredentialPools
			target.CredentialPoolsInRefillBackoff += source.CredentialPoolsInRefillBackoff
			target.UsableTickets += source.UsableTickets
			if source.RefillBackoffSeconds > target.RefillBackoffSeconds {
				target.RefillBackoffSeconds = source.RefillBackoffSeconds
			}
			if source.NearestTicketExpirySeconds > 0 &&
				(target.NearestTicketExpirySeconds == 0 || source.NearestTicketExpirySeconds < target.NearestTicketExpirySeconds) {
				target.NearestTicketExpirySeconds = source.NearestTicketExpirySeconds
			}
			if source.OldestVerificationAgeSeconds > target.OldestVerificationAgeSeconds {
				target.OldestVerificationAgeSeconds = source.OldestVerificationAgeSeconds
			}
			if target.verifiedBindings == nil {
				target.verifiedBindings = make(map[string]struct{})
				target.keyPossessionBindings = make(map[string]struct{})
				target.cooldownInstanceIDs = make(map[string]struct{})
			}
			for binding := range source.verifiedBindings {
				target.verifiedBindings[binding] = struct{}{}
			}
			for binding := range source.keyPossessionBindings {
				target.keyPossessionBindings[binding] = struct{}{}
			}
			for instanceID := range source.cooldownInstanceIDs {
				target.cooldownInstanceIDs[instanceID] = struct{}{}
			}
			target.MeasurementDigests = appendUniqueStrings(target.MeasurementDigests, source.MeasurementDigests...)
			target.MeasurementVersions = appendUniqueStrings(target.MeasurementVersions, source.MeasurementVersions...)
			target.VerifiedInstances = len(target.verifiedBindings)
			target.KeyPossessionVerifiedInstances = len(target.keyPossessionBindings)
			target.CooldownInstances = len(target.cooldownInstanceIDs)
			result[chuteID] = target
		}
	}
	for chuteID, state := range result {
		sort.Strings(state.MeasurementDigests)
		sort.Strings(state.MeasurementVersions)
		result[chuteID] = state
	}
	return result
}

func appendUniqueStrings(values []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(additions))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, value := range additions {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}
