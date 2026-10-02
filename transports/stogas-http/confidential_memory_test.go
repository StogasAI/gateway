package stogashttp

import (
	"net"
	"sync"
	"testing"
)

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
	quoteRelease()
	quoteRelease()
	if got := memory.reserved.Load(); got != sessionRetainedBytes {
		t.Fatal("quote release freed socket state", got)
	}
	client, server := net.Pipe()
	defer client.Close()
	conn := &confidentialConn{Conn: server, release: socketRelease}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() { _ = conn.Close() })
	}
	group.Wait()
	if memory.reserved.Load() != 0 {
		t.Fatal("closed socket leaked reservation")
	}
	var absent *requestMemoryAdmission
	if _, ok := absent.confidentialReservation(1)(); ok {
		t.Fatal("missing admission silently accepted setup")
	}
}
