package chutese2ee

import (
	"fmt"
	"testing"
	"time"
)

func TestTargetCapacityIsSharedAndIdleStateIsFullyReleased(t *testing.T) {
	d := &diagnostics{}
	first := newPoolState(nil, nil, d)
	second := newPoolState(nil, nil, d)
	defer first.close()
	defer second.close()
	for i := range maximumPoolTargets {
		target := ModelTarget{ChuteID: fmt.Sprintf("%08x-1111-4111-8111-111111111111", i), GPUCount: testGPUCount}
		if err := first.rememberTarget(target); err != nil {
			t.Fatal(err)
		}
	}
	if err := second.rememberTarget(testModelTarget); err != errCredentialUnavailable {
		t.Fatal("target budget was not shared")
	}
	first.maintain(time.Now().Add(credentialIdleLifetime))
	if d.poolTargets.Load() != 0 {
		t.Fatal("idle targets retained capacity")
	}
	if err := second.rememberTarget(testModelTarget); err != nil {
		t.Fatal(err)
	}
	second.pools[testChuteID] = &ticketPool{}
	second.verified[testChuteID] = map[string]verifiedInstance{testInstanceID: {}}
	second.cooldowns[testChuteID] = map[string]time.Time{testInstanceID: time.Now()}
	second.refillState[testChuteID] = &ticketRefillState{}
	second.maintain(time.Now().Add(credentialIdleLifetime))
	second.observeInvoke(reservedTicket{ChuteID: testChuteID, InstanceID: testInstanceID}, 503, 0, nil)
	if len(second.pools)+len(second.verified)+len(second.cooldowns)+len(second.refillState)+len(second.activity) != 0 {
		t.Fatal("idle state retained or late response resurrected it")
	}
	second.close()
	second.close()
	if d.poolTargets.Load() != 0 {
		t.Fatal("close corrupted capacity accounting")
	}
	if err := second.rememberTarget(testModelTarget); err == nil {
		t.Fatal("closed pool accepted a target")
	}
}

func TestRepeatedDiscoveryHasFiniteTicketAndVerificationState(t *testing.T) {
	state := newPoolState(nil, nil, &diagnostics{})
	defer state.close()
	for i := range maximumPooledTicketsPerTarget + 100 {
		state.install(testModelTarget, []discoveredInstance{{ID: testInstanceID, PublicKey: "key", Tickets: []string{fmt.Sprintf("%032d", i)}}}, time.Now().Add(time.Minute))
	}
	if got := len(state.pools[testChuteID].Instances[testInstanceID].Values); got != maximumPooledTicketsPerTarget {
		t.Fatalf("tickets = %d", got)
	}
	state.verified[testChuteID] = make(map[string]verifiedInstance)
	for i := range maximumDiscoveredInstances + 100 {
		state.storeVerifiedLocked(testChuteID, fmt.Sprint(i), verifiedInstance{ValidUntil: time.Now().Add(time.Minute)})
	}
	if len(state.verified[testChuteID]) != maximumDiscoveredInstances {
		t.Fatal("verification state exceeded capacity")
	}
}

func TestDiagnosticCardinalityIsBounded(t *testing.T) {
	d := &diagnostics{}
	for i := range maximumDiagnosticChutes + 100 {
		d.registerModel(fmt.Sprint(i), "model")
	}
	for i := range maximumDiagnosticModels + 100 {
		d.registerModel("latest", fmt.Sprint(i))
	}
	snapshot := d.snapshot(nil)
	if len(snapshot.Chutes) != maximumDiagnosticChutes {
		t.Fatal("chute diagnostics exceeded capacity")
	}
	for _, chute := range snapshot.Chutes {
		if len(chute.UpstreamModels) > maximumDiagnosticModels {
			t.Fatal("model diagnostics exceeded capacity")
		}
	}
}
