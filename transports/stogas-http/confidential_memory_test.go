package stogashttp

import (
	"net"
	"sync"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
)

func TestColdStateCannotConsumeRequestAdmissionHeadroom(t *testing.T) {
	memory := newRequestMemoryAdmission()
	const bodyBytes = 128 * 1024 * 1024
	if err := memory.protectRequestMemory(bodyBytes); err != nil {
		t.Fatal(err)
	}
	releases := make(chan func(), int(memory.budgetBytes()/encryptedSessionRetainedBytes))
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for {
				release, ok := memory.confidentialReservation(encryptedSessionRetainedBytes)()
				if !ok {
					return
				}
				releases <- release
			}
		})
	}
	workers.Wait()
	close(releases)
	defer func() {
		for release := range releases {
			release()
		}
	}()
	if len(releases) == 0 {
		t.Fatal("cold admission refused an empty gateway")
	}
	request, ok := memory.acquire(bodyBytes)
	if !ok {
		t.Fatal("idle state prevented a maximum request")
	}
	defer request.release()
	if err := request.admitJSON(catalog.MaxRequestJSONValues); err != nil {
		t.Fatal("idle state prevented structural admission", err)
	}
	response := memory.newLease(downstreamDeliveryMemory)
	if !response.grow(maxInferenceStreamResponseBytes) {
		t.Fatal("idle state prevented a bounded response")
	}
	response.release()
	request.release()
	if release, ok := memory.confidentialReservation(encryptedSessionRetainedBytes)(); ok {
		release()
		t.Fatal("completion lent protected headroom to more idle state")
	}
}

func TestConfidentialMemoryConfigurationCanFitOneCompleteSession(t *testing.T) {
	const bodyBytes = 128 * 1024 * 1024
	memory := newRequestMemoryAdmission()
	if err := memory.protectRequestMemory(bodyBytes); err != nil {
		t.Fatal(err)
	}
	minimumBudget := memory.confidentialHeadroom + encryptedSessionRetainedBytes + sessionRetainedBytes + quoteRetainedBytes
	for _, budget := range []int64{minimumBudget - 1, minimumBudget} {
		admission := &requestMemoryAdmission{budget: budget}
		err := admission.protectRequestMemory(bodyBytes)
		if (err != nil) != (budget < minimumBudget) {
			t.Fatalf("budget %d: %v", budget, err)
		}
		if err == nil {
			for _, size := range []int{encryptedSessionRetainedBytes, sessionRetainedBytes, quoteRetainedBytes} {
				release, ok := admission.confidentialReservation(size)()
				if !ok {
					t.Fatal("valid configuration refused session setup")
				}
				defer release()
			}
			request, ok := admission.acquire(bodyBytes)
			if !ok || request.admitJSON(catalog.MaxRequestJSONValues) != nil {
				t.Fatal("valid configuration refused maximum request")
			}
			defer request.release()
			response := admission.newLease(downstreamDeliveryMemory)
			if !response.grow(maxInferenceStreamResponseBytes) {
				t.Fatal("valid configuration refused bounded response")
			}
			defer response.release()
		}
	}
}

func TestConfidentialReservationsFollowConnectionAndSetupOwners(t *testing.T) {
	memory := &requestMemoryAdmission{budget: sessionRetainedBytes + quoteRetainedBytes}
	socketRelease, ok := memory.confidentialReservation(sessionRetainedBytes)()
	if !ok {
		t.Fatal("socket admission failed")
	}
	quoteRelease, ok := memory.confidentialReservation(quoteRetainedBytes)()
	if !ok {
		t.Fatal("quote admission failed")
	}
	if release, ok := memory.confidentialReservation(1)(); ok || release != nil {
		t.Fatal("overcommitted confidential state")
	}
	stats := memory.diagnostics()
	if stats.ConfidentialReservedBytes != sessionRetainedBytes+quoteRetainedBytes || stats.ConfidentialReservationFailures != 1 ||
		stats.StreamStateReservedBytes != 0 || stats.RequestReservedBytes != 0 || stats.ReservedBytes != stats.ConfidentialReservedBytes {
		t.Fatalf("confidential owners mixed with inference reservations: %+v", stats)
	}
	quoteRelease()
	quoteRelease()
	if got := memory.reserved.Load(); got != sessionRetainedBytes {
		t.Fatal("quote release freed socket state", got)
	}
	if got := memory.diagnostics().ConfidentialReservedBytes; got != sessionRetainedBytes {
		t.Fatal("quote release did not preserve the socket's diagnostic charge", got)
	}
	client, server := net.Pipe()
	defer client.Close()
	conn := &confidentialConn{Conn: server, release: socketRelease}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() { _ = conn.Close() })
	}
	group.Wait()
	if memory.reserved.Load() != 0 || memory.diagnostics().ConfidentialReservedBytes != 0 {
		t.Fatal("closed socket leaked reservation")
	}
	var absent *requestMemoryAdmission
	if _, ok := absent.confidentialReservation(1)(); ok {
		t.Fatal("missing admission silently accepted setup")
	}
}
