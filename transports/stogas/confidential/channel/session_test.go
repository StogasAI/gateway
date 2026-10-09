package channel

import (
	"bytes"
	"errors"
	"slices"
	"sync"
	"testing"
)

func TestSessionOnlyAuthenticatedFirstClaimantOwnsResponse(t *testing.T) {
	session, client := testServerSession(t)
	defer session.Close()
	encoder := newRecords(requestMessage(client, 42), client.ID, 42, requestDirection)
	response := responseRecords(client, 42)
	first := sealRecord(t, encoder, Metadata, []byte("credentials"))
	forged := slices.Clone(first)
	forged[len(forged)-1] ^= 1
	if request, _, err := session.AcceptStart(42, forged); request != nil || !errors.Is(err, ErrAuthentication) {
		t.Fatalf("invalid start was admitted: %v", err)
	}
	const parallel = 64
	winners := make(chan *ServerRequest, parallel)
	errorsSeen := make(chan error, parallel)
	var workers sync.WaitGroup
	for range parallel {
		workers.Go(func() {
			request, metadata, err := session.AcceptStart(42, slices.Clone(first))
			if err != nil {
				if request != nil || metadata != nil {
					errorsSeen <- errors.New("rejected claimant received state")
				} else {
					errorsSeen <- err
				}
				return
			}
			if !bytes.Equal(metadata, []byte("credentials")) {
				errorsSeen <- errors.New("metadata changed")
			}
			winners <- request
		})
	}
	workers.Wait()
	close(winners)
	close(errorsSeen)
	if len(winners) != 1 || len(errorsSeen) != parallel-1 {
		t.Fatalf("claimants: winners=%d rejected=%d", len(winners), len(errorsSeen))
	}
	for err := range errorsSeen {
		if !errors.Is(err, ErrReplay) {
			t.Fatal(err)
		}
	}
	request := <-winners
	defer request.Close()
	// Closing the reusable session cannot destroy
	// an admitted request's cipher or permit a duplicate response writer.
	session.Close()
	if request, _, err := session.AcceptStart(42, slices.Clone(first)); request != nil || !errors.Is(err, ErrClosed) {
		t.Fatalf("closed session admitted a start: %v", err)
	}
	for _, record := range []struct {
		kind Kind
		data []byte
	}{{Data, []byte("prompt")}, {Finished, nil}} {
		if _, _, err := request.Open(sealRecord(t, encoder, record.kind, record.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := request.Complete(); err != nil {
		t.Fatal(err)
	}
	encoded, err := request.Seal(Metadata, []byte("status=200"))
	if err != nil {
		t.Fatal(err)
	}
	if _, metadata, err := response.open(encoded); err != nil || string(metadata) != "status=200" {
		t.Fatalf("admitted response did not survive session close: %v", err)
	}
}

func TestSessionOutOfOrderAndRetiredStarts(t *testing.T) {
	session, client := testServerSession(t)
	defer session.Close()
	for _, number := range []uint64{100, 98, 99, 100 + ReplayWindow} {
		encoder := newRecords(requestMessage(client, number), client.ID, number, requestDirection)
		first := sealRecord(t, encoder, Metadata, []byte("credentials"))
		request, _, err := session.AcceptStart(number, first)
		if err != nil {
			t.Fatalf("out of order fresh start %d: %v", number, err)
		}
		request.Close()
	}
	for _, number := range []uint64{98, 99, 100, 100 + ReplayWindow} {
		encoder := newRecords(requestMessage(client, number), client.ID, number, requestDirection)
		request, metadata, err := session.AcceptStart(number, sealRecord(t, encoder, Metadata, []byte("credentials")))
		if !errors.Is(err, ErrReplay) || request != nil || metadata != nil {
			t.Fatalf("retired/duplicate start %d received cipher: %v", number, err)
		}
	}
}
