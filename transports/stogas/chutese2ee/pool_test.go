package chutese2ee

import (
	"context"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testChuteID    = "11111111-1111-4111-8111-111111111111"
	testInstanceID = "22222222-2222-4222-8222-222222222222"
	testGPUCount   = 8
)

var testModelTarget = ModelTarget{ChuteID: testChuteID, GPUCount: testGPUCount}

func TestValidateDiscoveryAcceptsCanonicalBatch(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	response := validDiscoveryForTest(t, now)
	instances, expiresAt, err := validateDiscovery(response, now)
	if err != nil {
		t.Fatalf("validate discovery: %v", err)
	}
	if len(instances) != 1 {
		t.Fatalf("instance count = %d", len(instances))
	}
	wantExpiry := now.Add(55 * time.Second)
	if !expiresAt.Equal(wantExpiry) {
		t.Fatalf("usable expiry = %s, want %s", expiresAt, wantExpiry)
	}
}

func TestValidateDiscoveryRejectsUnsafeResponses(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	base := validDiscoveryForTest(t, now)
	tests := map[string]func(*discoveryResponse){
		"no instances": func(value *discoveryResponse) { value.Instances = nil },
		"bad instance ID": func(value *discoveryResponse) {
			value.Instances[0].ID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
		},
		"duplicate instance": func(value *discoveryResponse) {
			value.Instances = append(value.Instances, value.Instances[0])
		},
		"bad public key": func(value *discoveryResponse) { value.Instances[0].PublicKey = "bad" },
		"no tickets":     func(value *discoveryResponse) { value.Instances[0].Tickets = nil },
		"bad ticket":     func(value *discoveryResponse) { value.Instances[0].Tickets[0] = "not-a-ticket" },
		"duplicate ticket": func(value *discoveryResponse) {
			value.Instances[0].Tickets = append(value.Instances[0].Tickets, value.Instances[0].Tickets[0])
		},
		"expired": func(value *discoveryResponse) {
			value.ExpiresAtUnix = now.Add(4 * time.Second).Unix()
		},
		"excess duration": func(value *discoveryResponse) { value.ExpiresIn = 76 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := cloneDiscoveryForTest(base)
			mutate(&value)
			if _, _, err := validateDiscovery(value, now); err == nil {
				t.Fatal("expected discovery validation failure")
			}
		})
	}
}

func TestTicketReservationIsAtomicAndNeverReusesTicket(t *testing.T) {
	now := time.Now()
	state := newPoolState(nil, nil, &diagnostics{})
	defer state.close()
	state.verified[testChuteID] = map[string]verifiedInstance{
		testInstanceID: {
			InstanceID: testInstanceID,
			PublicKey:  "key",
			GPUCount:   testGPUCount,
			VerifiedAt: now,
			ValidUntil: now.Add(time.Minute),
		},
	}
	values := make([]string, 50)
	for index := range values {
		values[index] = fmt.Sprintf("ticket-%02d", index)
	}
	state.pools[testChuteID] = &ticketPool{
		Instances: map[string]*instanceTickets{
			testInstanceID: {PublicKey: "key", Values: pooledTicketsForTest(now.Add(time.Minute), values...)},
		},
		Order: []string{testInstanceID},
	}

	reserved := make(chan string, len(values))
	var wait sync.WaitGroup
	for range values {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ticket, ok := state.take(testModelTarget, now)
			if ok {
				reserved <- ticket.Value
			}
		}()
	}
	wait.Wait()
	close(reserved)
	seen := make(map[string]struct{}, len(values))
	for value := range reserved {
		if _, duplicate := seen[value]; duplicate {
			t.Fatalf("ticket %q was reserved more than once", value)
		}
		seen[value] = struct{}{}
	}
	if len(seen) != len(values) {
		t.Fatalf("reserved %d tickets, want %d", len(seen), len(values))
	}
	if _, ok := state.take(testModelTarget, now); ok {
		t.Fatal("expected the exhausted pool to reject another reservation")
	}
}

func TestColdBurstCanUseTwoDiscoveryBatches(t *testing.T) {
	instanceKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.StdEncoding.EncodeToString(instanceKey.EncapsulationKey().Bytes())
	var discoveryCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != discoveryPathPrefix+testChuteID {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		call := int(discoveryCalls.Add(1))
		tickets := make([]string, 10)
		for index := range tickets {
			tickets[index] = fmt.Sprintf("%032d", call*100+index)
		}
		now := time.Now()
		response.Header().Set("Content-Type", "application/json")
		if encodeErr := json.NewEncoder(response).Encode(discoveryResponse{
			Instances: []discoveredInstance{{
				ID:        testInstanceID,
				PublicKey: publicKey,
				Tickets:   tickets,
			}},
			ExpiresIn:     60,
			ExpiresAtUnix: now.Add(time.Minute).Unix(),
		}); encodeErr != nil {
			t.Errorf("encode discovery: %v", encodeErr)
		}
	}))
	defer server.Close()

	api, err := newAPIClient("managed-key", server.URL, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer api.close()
	state := newPoolState(api, nil, &diagnostics{})
	defer state.close()
	state.verified[testChuteID] = map[string]verifiedInstance{
		testInstanceID: {
			InstanceID: testInstanceID,
			PublicKey:  publicKey,
			GPUCount:   testGPUCount,
			ValidUntil: time.Now().Add(time.Minute),
		},
	}
	// Keep this test focused on synchronous burst refill. Production can also
	// start the normal low-water background refill.
	state.warming[testChuteID] = true

	const requests = 15
	start := make(chan struct{})
	results := make(chan reservedTicket, requests)
	errorsFound := make(chan error, requests)
	var wait sync.WaitGroup
	for range requests {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			ticket, reserveErr := state.reserve(t.Context(), testModelTarget)
			if reserveErr != nil {
				errorsFound <- reserveErr
				return
			}
			results <- ticket
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsFound)
	for reserveErr := range errorsFound {
		t.Errorf("reserve cold burst ticket: %v", reserveErr)
	}
	seen := make(map[string]struct{}, requests)
	for ticket := range results {
		if _, duplicate := seen[ticket.Value]; duplicate {
			t.Errorf("ticket %q was reserved twice", ticket.Value)
		}
		seen[ticket.Value] = struct{}{}
	}
	if len(seen) != requests {
		t.Fatalf("reserved %d burst tickets, want %d", len(seen), requests)
	}
	if got := discoveryCalls.Load(); got != 2 {
		t.Fatalf("discovery calls = %d, want 2", got)
	}
}

func TestTicketReservationStopsWaitingAtRequestDeadline(t *testing.T) {
	state := newPoolState(nil, nil, &diagnostics{})
	defer state.close()
	started := make(chan struct{})
	release := make(chan struct{})
	flight := state.refills.DoChan(modelTargetKey(testModelTarget), func() (any, error) {
		close(started)
		<-release
		return nil, nil
	})
	<-started

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	startedAt := time.Now()
	_, err := state.reserve(ctx, testModelTarget)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reservation error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(startedAt); elapsed > 200*time.Millisecond {
		t.Fatalf("reservation deadline took %s, want a bounded wait", elapsed)
	}
	close(release)
	<-flight
}

func TestTicketReservationUsesRoundRobinAcrossVerifiedInstances(t *testing.T) {
	now := time.Now()
	state := newPoolState(nil, nil, &diagnostics{})
	defer state.close()
	secondInstance := "33333333-3333-4333-8333-333333333333"
	state.verified[testChuteID] = map[string]verifiedInstance{
		testInstanceID: {GPUCount: testGPUCount, PublicKey: "key-a", ValidUntil: now.Add(time.Minute)},
		secondInstance: {GPUCount: testGPUCount, PublicKey: "key-b", ValidUntil: now.Add(time.Minute)},
	}
	state.pools[testChuteID] = &ticketPool{
		Instances: map[string]*instanceTickets{
			testInstanceID: {PublicKey: "key-a", Values: pooledTicketsForTest(now.Add(time.Minute), "a1", "a2")},
			secondInstance: {PublicKey: "key-b", Values: pooledTicketsForTest(now.Add(time.Minute), "b1", "b2")},
		},
		Order: []string{testInstanceID, secondInstance},
	}
	for index, want := range []string{testInstanceID, secondInstance, testInstanceID, secondInstance} {
		ticket, ok := state.take(testModelTarget, now)
		if !ok || ticket.InstanceID != want {
			t.Fatalf("reservation %d instance = %q, want %q", index, ticket.InstanceID, want)
		}
	}
}

func TestInvokeOutcomeInvalidatesOnlyUnsafeState(t *testing.T) {
	tests := []struct {
		name                string
		status              int
		err                 error
		wantTickets         bool
		wantVerification    bool
		wantCooldown        bool
		wantCooldownAtLeast time.Duration
	}{
		{name: "success", status: http.StatusOK, wantTickets: true, wantVerification: true},
		{name: "bad request burns only reserved ticket", status: http.StatusBadRequest, wantTickets: true, wantVerification: true},
		{name: "forbidden invalidates issued tickets", status: http.StatusForbidden, wantVerification: true},
		{name: "not found invalidates instance", status: http.StatusNotFound, wantCooldown: true, wantCooldownAtLeast: 25 * time.Second},
		{name: "gone invalidates instance", status: http.StatusGone, wantCooldown: true, wantCooldownAtLeast: 25 * time.Second},
		{name: "rate limited keeps tickets", status: http.StatusTooManyRequests, wantTickets: true, wantVerification: true, wantCooldown: true},
		{name: "upstream unavailable keeps tickets", status: http.StatusServiceUnavailable, wantTickets: true, wantVerification: true, wantCooldown: true},
		{name: "ambiguous transport failure invalidates tickets", err: errors.New("connection reset"), wantVerification: true, wantCooldown: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now()
			state := newPoolState(nil, nil, &diagnostics{})
			defer state.close()
			state.verified[testChuteID] = map[string]verifiedInstance{
				testInstanceID: {GPUCount: testGPUCount, PublicKey: "key", ValidUntil: now.Add(time.Minute)},
			}
			state.pools[testChuteID] = &ticketPool{
				Instances: map[string]*instanceTickets{
					testInstanceID: {PublicKey: "key", Values: pooledTicketsForTest(now.Add(time.Minute), "remaining")},
				},
				Order: []string{testInstanceID},
			}
			state.observeInvoke(
				reservedTicket{ChuteID: testChuteID, InstanceID: testInstanceID},
				test.status,
				0,
				test.err,
			)
			state.mu.Lock()
			hasTickets := false
			if pool := state.pools[testChuteID]; pool != nil {
				_, hasTickets = pool.Instances[testInstanceID]
			}
			_, hasVerification := state.verified[testChuteID][testInstanceID]
			cooldownUntil := state.cooldowns[testChuteID][testInstanceID]
			state.mu.Unlock()
			if hasTickets != test.wantTickets {
				t.Fatalf("has tickets = %t, want %t", hasTickets, test.wantTickets)
			}
			if hasVerification != test.wantVerification {
				t.Fatalf("has verification = %t, want %t", hasVerification, test.wantVerification)
			}
			if cooldownUntil.After(now) != test.wantCooldown {
				t.Fatalf("has cooldown = %t, want %t", cooldownUntil.After(now), test.wantCooldown)
			}
			if test.wantCooldownAtLeast > 0 && time.Until(cooldownUntil) < test.wantCooldownAtLeast {
				t.Fatalf("cooldown = %s, want at least %s", time.Until(cooldownUntil), test.wantCooldownAtLeast)
			}
		})
	}
}

func TestForbiddenInvokeInvalidatesTheWholeIssuedBatch(t *testing.T) {
	now := time.Now()
	state := newPoolState(nil, nil, &diagnostics{})
	defer state.close()
	secondInstance := "33333333-3333-4333-8333-333333333333"
	state.verified[testChuteID] = map[string]verifiedInstance{
		testInstanceID: {GPUCount: testGPUCount, PublicKey: "key-a", ValidUntil: now.Add(time.Minute)},
		secondInstance: {GPUCount: testGPUCount, PublicKey: "key-b", ValidUntil: now.Add(time.Minute)},
	}
	state.pools[testChuteID] = &ticketPool{
		Instances: map[string]*instanceTickets{
			testInstanceID: {PublicKey: "key-a", Values: pooledTicketsForTest(now.Add(time.Minute), "remaining-a")},
			secondInstance: {PublicKey: "key-b", Values: pooledTicketsForTest(now.Add(time.Minute), "remaining-b")},
		},
		Order: []string{testInstanceID, secondInstance},
	}

	state.observeInvoke(
		reservedTicket{ChuteID: testChuteID, InstanceID: testInstanceID},
		http.StatusForbidden,
		0,
		nil,
	)
	state.mu.Lock()
	_, hasPool := state.pools[testChuteID]
	verifiedCount := len(state.verified[testChuteID])
	state.mu.Unlock()
	if hasPool {
		t.Fatal("forbidden nonce response retained sibling tickets from the issued batch")
	}
	if verifiedCount != 2 {
		t.Fatalf("verified instances = %d, want 2", verifiedCount)
	}
}

func TestTicketPoolRejectsChangedOrExpiredAttestation(t *testing.T) {
	now := time.Now()
	state := newPoolState(nil, nil, &diagnostics{})
	defer state.close()
	state.pools[testChuteID] = &ticketPool{
		Instances: map[string]*instanceTickets{
			testInstanceID: {PublicKey: "new-key", Values: pooledTicketsForTest(now.Add(time.Minute), "ticket")},
		},
		Order: []string{testInstanceID},
	}
	state.verified[testChuteID] = map[string]verifiedInstance{
		testInstanceID: {GPUCount: testGPUCount, PublicKey: "old-key", ValidUntil: now.Add(time.Minute)},
	}
	if _, ok := state.take(testModelTarget, now); ok {
		t.Fatal("expected changed public key to require new attestation")
	}
	state.verified[testChuteID][testInstanceID] = verifiedInstance{GPUCount: testGPUCount, PublicKey: "new-key", ValidUntil: now.Add(-time.Second)}
	if _, ok := state.take(testModelTarget, now); ok {
		t.Fatal("expected expired attestation to reject ticket")
	}
}

func TestNewInstanceKeyBypassesScheduledRefresh(t *testing.T) {
	attestor := &attestor{
		cache:    make(map[string]verifiedInstance),
		observed: make(map[string]map[string]observedAttestationInstance),
		refresh:  make(map[string]*attestationRefreshState),
	}
	attestor.observe(testModelTarget, []discoveredInstance{{ID: testInstanceID, PublicKey: "known-key"}})
	attestor.refreshMu.Lock()
	attestor.refresh[testChuteID].NextAttempt = time.Now().Add(time.Minute)
	attestor.refreshMu.Unlock()

	attestor.observe(testModelTarget, []discoveredInstance{{ID: testInstanceID, PublicKey: "known-key"}})
	attestor.refreshMu.Lock()
	knownNext := attestor.refresh[testChuteID].NextAttempt
	attestor.refreshMu.Unlock()
	if time.Until(knownNext) < 50*time.Second {
		t.Fatal("known instance key did not honor the normal refresh schedule")
	}

	attestor.observe(testModelTarget, []discoveredInstance{{ID: testInstanceID, PublicKey: "changed-key"}})
	attestor.refreshMu.Lock()
	changedNext := attestor.refresh[testChuteID].NextAttempt
	attestor.refreshMu.Unlock()
	if time.Until(changedNext) > time.Second {
		t.Fatal("changed instance key did not request immediate evidence")
	}
}

func TestTicketBatchesMergeWithIndependentExpiry(t *testing.T) {
	now := time.Now()
	state := newPoolState(nil, nil, &diagnostics{})
	defer state.close()
	firstExpiry := now.Add(30 * time.Second)
	secondExpiry := now.Add(time.Minute)
	state.install(testModelTarget, []discoveredInstance{{
		ID: testInstanceID, PublicKey: "key", Tickets: []string{"first"},
	}}, firstExpiry)
	state.install(testModelTarget, []discoveredInstance{{
		ID: testInstanceID, PublicKey: "key", Tickets: []string{"second"},
	}}, secondExpiry)
	state.mu.Lock()
	tickets := append([]pooledTicket(nil), state.pools[testChuteID].Instances[testInstanceID].Values...)
	state.mu.Unlock()
	if len(tickets) != 2 || tickets[0].Value != "first" || tickets[1].Value != "second" ||
		!tickets[0].ExpiresAt.Equal(firstExpiry) || !tickets[1].ExpiresAt.Equal(secondExpiry) {
		t.Fatalf("merged tickets = %#v", tickets)
	}
}

func TestSharedAttestationMakesStoredTicketUsable(t *testing.T) {
	now := time.Now()
	shared := &attestor{cache: make(map[string]verifiedInstance)}
	state := newPoolState(nil, shared, &diagnostics{})
	defer state.close()
	state.install(testModelTarget, []discoveredInstance{{
		ID: testInstanceID, PublicKey: "key", Tickets: []string{"ticket"},
	}}, now.Add(time.Minute))
	if _, ok := state.take(testModelTarget, now); ok {
		t.Fatal("ticket was usable before attestation")
	}
	shared.storeCachedInstances(testModelTarget, map[string]verifiedInstance{
		testInstanceID: {
			InstanceID: testInstanceID,
			PublicKey:  "key",
			GPUCount:   testGPUCount,
			VerifiedAt: now,
			ValidUntil: now.Add(time.Minute),
		},
	})
	if ticket, ok := state.take(testModelTarget, now); !ok || ticket.Value != "ticket" {
		t.Fatalf("ticket after shared attestation = %#v usable=%t", ticket, ok)
	}
}

func TestAdaptiveRefillHandlesLowAndHighDemand(t *testing.T) {
	now := time.Now()
	state := newPoolState(nil, nil, &diagnostics{})
	defer state.close()
	state.verified[testChuteID] = map[string]verifiedInstance{
		testInstanceID: {GPUCount: testGPUCount, PublicKey: "key", ValidUntil: now.Add(time.Minute)},
	}
	state.pools[testChuteID] = &ticketPool{
		Instances: map[string]*instanceTickets{
			testInstanceID: {PublicKey: "key", Values: pooledTicketsForTest(now.Add(14*time.Second), "one", "two")},
		},
		Order: []string{testInstanceID},
	}
	state.activity[testChuteID] = &ticketActivity{
		Target:       testModelTarget,
		LastDemandAt: now,
		LastRefillAt: now.Add(-time.Second),
		Takes:        []time.Time{now},
	}
	if !state.shouldWarmLocked(testChuteID, now) {
		t.Fatal("low-volume pool did not refresh before its last tickets expired")
	}
	state.activity[testChuteID].LastRefillAt = now.Add(time.Millisecond)
	if state.shouldWarmLocked(testChuteID, now) {
		t.Fatal("pool refilled again without demand after its last refill")
	}
	state.activity[testChuteID].LastRefillAt = now.Add(-time.Second)
	state.pools[testChuteID].Instances[testInstanceID].Values = pooledTicketsForTest(
		now.Add(time.Minute), "one", "two",
	)
	state.activity[testChuteID].Takes = []time.Time{
		now.Add(-2 * time.Second), now.Add(-time.Second), now,
	}
	if !state.shouldWarmLocked(testChuteID, now) {
		t.Fatal("high-demand pool did not refill before projected depletion")
	}
}

func TestTicketRefillBackoffStopsRetryStorms(t *testing.T) {
	state := newPoolState(nil, nil, &diagnostics{})
	defer state.close()
	rateLimit := &httpStatusError{
		Operation:  "GET discovery",
		StatusCode: http.StatusTooManyRequests,
		RetryAfter: 5 * time.Second,
	}
	state.recordRefillResult(testChuteID, rateLimit)

	state.mu.Lock()
	refill := state.refillState[testChuteID]
	allowed := state.canRefillLocked(testChuteID, time.Now())
	state.mu.Unlock()
	if refill == nil || allowed || time.Until(refill.NotBefore) < 4*time.Second {
		t.Fatalf("refill backoff = %#v allowed=%t", refill, allowed)
	}

	err := state.refill(testModelTarget)
	var backoff *ticketRefillBackoffError
	var retainedStatus *httpStatusError
	if !errors.As(err, &backoff) || backoff.RetryAfter <= 0 ||
		!errors.As(err, &retainedStatus) || retainedStatus.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("backoff error = %v", err)
	}
	health := state.health()[testChuteID]
	if health.RefillBackoffSeconds < 1 || health.RefillBackoffSeconds > 5 {
		t.Fatalf("reported refill backoff = %d", health.RefillBackoffSeconds)
	}

	state.recordRefillResult(testChuteID, nil)
	state.mu.Lock()
	_, retained := state.refillState[testChuteID]
	state.mu.Unlock()
	if retained {
		t.Fatal("successful refill did not clear backoff")
	}
}

func TestColdReservationWaitsForShortTransientRefillBackoff(t *testing.T) {
	instanceKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.StdEncoding.EncodeToString(instanceKey.EncapsulationKey().Bytes())
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != discoveryPathPrefix+testChuteID {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		now := time.Now()
		_ = json.NewEncoder(response).Encode(discoveryResponse{
			Instances: []discoveredInstance{{
				ID:        testInstanceID,
				PublicKey: publicKey,
				Tickets:   []string{strings.Repeat("R", 32)},
			}},
			ExpiresIn:     60,
			ExpiresAtUnix: now.Add(time.Minute).Unix(),
		})
	}))
	defer server.Close()
	api, err := newAPIClient("managed-key", server.URL, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer api.close()
	state := newPoolState(api, nil, &diagnostics{})
	defer state.close()
	state.verified[testChuteID] = map[string]verifiedInstance{
		testInstanceID: {
			InstanceID: testInstanceID,
			PublicKey:  publicKey,
			GPUCount:   testGPUCount,
			ValidUntil: time.Now().Add(time.Minute),
		},
	}
	state.refillState[testChuteID] = &ticketRefillState{
		Failures:  1,
		LastError: &httpStatusError{StatusCode: http.StatusServiceUnavailable},
		NotBefore: time.Now().Add(25 * time.Millisecond),
	}

	started := time.Now()
	ticket, err := state.reserve(t.Context(), testModelTarget)
	if err != nil || ticket.Value != strings.Repeat("R", 32) {
		t.Fatalf("reserve after short backoff: ticket=%#v error=%v", ticket, err)
	}
	if time.Since(started) < 20*time.Millisecond {
		t.Fatal("reservation did not honor the active refill backoff")
	}
}

func validDiscoveryForTest(t *testing.T, now time.Time) discoveryResponse {
	t.Helper()
	key, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	return discoveryResponse{
		Instances: []discoveredInstance{{
			ID:        testInstanceID,
			PublicKey: base64.StdEncoding.EncodeToString(key.EncapsulationKey().Bytes()),
			Tickets:   []string{strings.Repeat("A", 32)},
		}},
		ExpiresIn:     60,
		ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}
}

func cloneDiscoveryForTest(value discoveryResponse) discoveryResponse {
	clone := value
	clone.Instances = append([]discoveredInstance(nil), value.Instances...)
	for index := range clone.Instances {
		clone.Instances[index].Tickets = append([]string(nil), value.Instances[index].Tickets...)
	}
	return clone
}

func pooledTicketsForTest(expiresAt time.Time, values ...string) []pooledTicket {
	tickets := make([]pooledTicket, 0, len(values))
	for _, value := range values {
		tickets = append(tickets, pooledTicket{Value: value, ExpiresAt: expiresAt})
	}
	return tickets
}
