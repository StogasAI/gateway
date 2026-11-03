package billing

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	verifier "github.com/StogasAI/stogas/go"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/transports/stogas/billing/batchtest"
)

// testLogNode is the attested node of the boots in these tests.
const testLogNode = "amber-anchor-00"

// bootLogSigner signs with a fresh boot's key through the verifier, as the confidential
// runtime does.
type bootLogSigner struct {
	keys   *verifier.NodeKeys
	boot   [32]byte
	public []byte
}

func newBootLogSigner(t *testing.T) *bootLogSigner {
	t.Helper()
	keys, err := verifier.GenerateNodeKeys(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Close)
	report := make([]byte, 0x4a0)
	data, err := keys.ReportData(1, [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	copy(report[0x50:], data[:])
	document, err := keys.BootDocument(1, [32]byte{1}, [32]byte{2}, report, [32]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	var boot struct {
		ReportData struct {
			SigningPublicKey string `json:"signing_public_key"`
		} `json:"report_data"`
	}
	if err := json.Unmarshal(document, &boot); err != nil {
		t.Fatal(err)
	}
	public, err := base64.RawURLEncoding.DecodeString(boot.ReportData.SigningPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &bootLogSigner{keys: keys, boot: sha256.Sum256(document), public: public}
}

func (s *bootLogSigner) NodeID() string                          { return testLogNode }
func (s *bootLogSigner) LogRowLeaf(row []byte) ([64]byte, error) { return verifier.LogRowLeaf(row) }
func (s *bootLogSigner) SignLogBatch(sequence uint32, openedAt, sealedAt time.Time, leaves [][64]byte) ([]byte, error) {
	return s.keys.SignLogBatch(s.boot, testLogNode, sequence, openedAt, sealedAt, leaves)
}

// countingLogSigner hashes rows and records each batch instead of signing it, so tests follow
// sealing without the boot key's cost. Its batch JSON names only the batch's number.
type countingLogSigner struct {
	mu      sync.Mutex
	fail    bool
	batches []countedLogBatch
}

type countedLogBatch struct {
	sequence           uint32
	openedAt, sealedAt time.Time
	leaves             int
}

func (s *countingLogSigner) NodeID() string                          { return testLogNode }
func (s *countingLogSigner) LogRowLeaf(row []byte) ([64]byte, error) { return sha512.Sum512(row), nil }
func (s *countingLogSigner) SignLogBatch(sequence uint32, openedAt, sealedAt time.Time, leaves [][64]byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return nil, errors.New("the boot's signing key is closed")
	}
	s.batches = append(s.batches, countedLogBatch{sequence, openedAt, sealedAt, len(leaves)})
	return fmt.Appendf(nil, `{"sequence":%d}`, sequence), nil
}

func (s *countingLogSigner) sealed() []countedLogBatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.batches)
}

// placeTestRow gives a final log its place, as finalization does, and returns the place.
func placeTestRow(t *testing.T, s *Service) *LogPosition {
	t.Helper()
	event := testGatewayRequestEvent()
	event.NodeID = testLogNode
	if _, err := s.encodeSignedRow(&event); err != nil {
		t.Fatal(err)
	}
	return event.LogBatch
}

func sealOpenBatch(s *Service, now time.Time) {
	b := &s.logBatches
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sealLocked(now)
}

// storedSequences returns the number of each batch that the database stored, in order.
func storedSequences(t *testing.T, db *fakeSettlementDatabase) []uint32 {
	t.Helper()
	var sequences []uint32
	for _, line := range db.storedBatches() {
		var batch struct {
			Sequence uint32 `json:"sequence"`
		}
		if err := json.Unmarshal([]byte(line), &batch); err != nil {
			t.Fatal(err)
		}
		sequences = append(sequences, batch.Sequence)
	}
	return sequences
}

// settledRows returns each row as settlement stores it, by request ID: a final log without
// its hold binding, re-encoded with other key order and spacing as jsonb would, and a
// rejection as sent.
func settledRows(t *testing.T, db *fakeSettlementDatabase) map[string][]byte {
	t.Helper()
	rows := map[string][]byte{}
	for _, call := range db.recorded() {
		for _, raw := range slices.Concat(call.logs, call.rejections) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			delete(fields, "hold_params_hash")
			row, err := json.MarshalIndent(fields, "", " ")
			if err != nil {
				t.Fatal(err)
			}
			var id string
			if err := json.Unmarshal(fields["request_id"], &id); err != nil {
				t.Fatal(err)
			}
			if _, repeated := rows[id]; repeated {
				t.Fatalf("settlement received the row of %s twice", id)
			}
			rows[id] = row
		}
	}
	return rows
}

// Every row that the gateway stores, a final log or a rejection's own row or count, and every
// export of one, is the leaf at the place it names in a batch that the boot's key signs. The
// checker hashes and verifies apart from the Rust signer, so both must agree on what a row's
// leaf covers.
func TestStoredRowsAndTheirExportsAreLeavesOfASignedBatch(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	service := db.service
	signer := newBootLogSigner(t)
	service.SetLogSigner(signer)
	exports := newExportLog(t)

	authorization, final := settlementRequest(t, service)
	final.NodeID = testLogNode
	final.ReceiptCommitments = &ReceiptCommitments{Request: strings.Repeat("ab", 32), Response: strings.Repeat("cd", 32)}
	if err := service.FinalizeRequest(authorization, &final); err != nil {
		t.Fatal(err)
	}
	if final.LogBatch == nil || *final.LogBatch != (LogPosition{Sequence: 1}) {
		t.Fatalf("the first row took %+v, want the first place of batch 1", final.LogBatch)
	}
	// One minute has ended, so the sender places its count when it next ticks; the other
	// minute's count takes its place when the gateway closes.
	input := rejectionFixture()
	input.NodeID = testLogNode
	ended, open := input.CreatedAt.Add(-2*time.Minute), input.CreatedAt.Add(time.Hour)
	for _, at := range []time.Time{ended, open} {
		for range rejectionLogIndividualLimit + 2 {
			input.RequestID, input.CreatedAt = uuid.Must(uuid.NewV7()).String(), at
			service.RecordRejection(input, exports.export(input.RequestID))
		}
	}
	rejected := func() (total uint32) {
		for _, raw := range rejectionRows(db) {
			var row RequestEvent
			if err := json.Unmarshal(raw, &row); err != nil {
				t.Fatal(err)
			}
			total += row.RequestCount
		}
		return total
	}
	// Everything but the open minute's two counted repeats.
	waitFor(t, func() bool { return rejected() == 2*rejectionLogIndividualLimit+2 })
	service.CloseRejectionLogs()
	service.SealLogBatches()
	drainSettlements(t, service)
	if total := rejected(); total != 2*(rejectionLogIndividualLimit+2) {
		t.Fatalf("settlement holds %d rejections", total)
	}

	lines := db.storedBatches()
	if len(lines) != 1 {
		t.Fatalf("the database stored %d batches", len(lines))
	}
	stored := settledRows(t, db)
	rows := make([][]byte, 0, len(stored))
	indexes := make([]uint32, 0, len(stored))
	for id, row := range stored {
		var place struct {
			LogBatch           *LogPosition        `json:"log_batch"`
			ReceiptCommitments *ReceiptCommitments `json:"receipt_commitments"`
		}
		if err := json.Unmarshal(row, &place); err != nil {
			t.Fatal(err)
		}
		if place.LogBatch == nil {
			t.Fatalf("the row of %s names no batch: %s", id, row)
		}
		if commitments := place.ReceiptCommitments; (id == final.RequestID) != (commitments != nil) ||
			commitments != nil && *commitments != *final.ReceiptCommitments {
			t.Fatalf("the row of %s holds commitments %+v", id, commitments)
		}
		rows = append(rows, row)
		indexes = append(indexes, place.LogBatch.Index)
	}
	batch, err := batchtest.Verify(signer.public, signer.boot, []byte(lines[0]), rows...)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Sequence != 1 || batch.NodeID != testLogNode || int(batch.LeafCount) != len(rows) {
		t.Fatalf("the batch is %+v for %d rows", batch, len(rows))
	}
	// Places leave no gap: the batch holds no leaf that settlement never received.
	slices.Sort(indexes)
	for i, index := range indexes {
		if index != uint32(i) {
			t.Fatalf("the rows hold places %v", indexes)
		}
	}

	// An export carries the stored row: the final event, and each rejection's own row or
	// the count that holds it.
	exported := [][]byte{}
	if encoded, err := json.Marshal(final); err != nil {
		t.Fatal(err)
	} else {
		exported = append(exported, encoded)
	}
	exports.mu.Lock()
	for _, row := range exports.rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		exported = append(exported, encoded)
	}
	exports.mu.Unlock()
	// Each rejection row leaves with one export: its own, or a count's first repeat's.
	if want := 1 + len(rejectionRows(db)); len(exported) != want {
		t.Fatalf("%d exports left, want %d", len(exported), want)
	}
	if _, err := batchtest.Verify(signer.public, signer.boot, []byte(lines[0]), exported...); err != nil {
		t.Fatal(err)
	}

	diagnostics := service.logBatchDiagnostics()
	if diagnostics.Signing || diagnostics.Sequence != 1 || diagnostics.SignedRows != uint64(len(rows)) ||
		diagnostics.UnsignedRows != 0 || diagnostics.StoredBatches != 1 || diagnostics.DroppedBatches != 0 ||
		diagnostics.PendingBatches != 0 || diagnostics.OpenRows != 0 {
		t.Fatalf("diagnostics are %+v", diagnostics)
	}
}

// A row stays unsigned, with a null place, when it names another node, when RFC 8785 cannot
// hold it exactly, or after the gateway sealed its last batch. It still settles, and the next
// row that can be signed takes the first place, so batch numbers leave no gap.
func TestRowsThatCannotBeSignedSettleWithoutAPlace(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	service := db.service
	signer := newBootLogSigner(t)
	service.SetLogSigner(signer)
	finalize := func(change func(*RequestEvent)) RequestEvent {
		t.Helper()
		authorization, event := settlementRequest(t, service)
		event.NodeID = testLogNode
		change(&event)
		if err := service.FinalizeRequest(authorization, &event); err != nil {
			t.Fatal(err)
		}
		return event
	}
	huge := uint64(math.MaxUint64)
	unsigned := map[string]RequestEvent{
		"another node's": finalize(func(event *RequestEvent) { event.NodeID = "other-anchor-01" }),
		"an inexact":     finalize(func(event *RequestEvent) { event.CatalogVersion = &huge }),
	}
	signed := finalize(func(*RequestEvent) {})
	service.SealLogBatches()
	unsigned["a late"] = finalize(func(*RequestEvent) {})
	drainSettlements(t, service)

	if signed.LogBatch == nil || *signed.LogBatch != (LogPosition{Sequence: 1}) {
		t.Fatalf("the signed row took %+v", signed.LogBatch)
	}
	stored := settledRows(t, db)
	for name, event := range unsigned {
		row := stored[event.RequestID]
		if event.LogBatch != nil || !strings.Contains(string(row), `"log_batch": null`) {
			t.Errorf("%s row took %+v and settled as %s", name, event.LogBatch, row)
		}
	}
	lines := db.storedBatches()
	if len(lines) != 1 {
		t.Fatalf("the database stored %d batches", len(lines))
	}
	if _, err := batchtest.Verify(signer.public, signer.boot, []byte(lines[0]), stored[signed.RequestID]); err != nil {
		t.Fatal(err)
	}
	if diagnostics := service.logBatchDiagnostics(); diagnostics.SignedRows != 1 || diagnostics.UnsignedRows != 3 {
		t.Fatalf("diagnostics are %+v", diagnostics)
	}
}

// Without a boot key, rows name no batch and the gateway stores none.
func TestRowsWithoutABootKeyNameNoBatch(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	service := db.service
	authorization, event := settlementRequest(t, service)
	if err := service.FinalizeRequest(authorization, &event); err != nil {
		t.Fatal(err)
	}
	drainSettlements(t, service)
	row := string(settledRows(t, db)[event.RequestID])
	if !strings.Contains(row, `"log_batch": null`) || !strings.Contains(row, `"receipt_commitments": null`) {
		t.Fatalf("the row settled as %s", row)
	}
	if lines := db.storedBatches(); len(lines) != 0 {
		t.Fatalf("the database stored %v", lines)
	}
	if diagnostics := service.logBatchDiagnostics(); diagnostics != (LogBatchDiagnostics{}) {
		t.Fatalf("diagnostics are %+v", diagnostics)
	}
}

// A batch closes once it holds maxLogBatchLeaves rows, and the next row opens the next batch.
func TestFullBatchesCloseAndTheNextRowOpensAnother(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	service := db.service
	signer := &countingLogSigner{}
	service.SetLogSigner(signer)
	for index := range uint32(maxLogBatchLeaves) {
		if place := placeTestRow(t, service); place == nil || *place != (LogPosition{Sequence: 1, Index: index}) {
			t.Fatalf("row %d took %+v", index, place)
		}
	}
	if sealed := signer.sealed(); len(sealed) != 1 || sealed[0].sequence != 1 || sealed[0].leaves != maxLogBatchLeaves {
		t.Fatalf("sealed %+v", sealed)
	}
	if place := placeTestRow(t, service); place == nil || *place != (LogPosition{Sequence: 2}) {
		t.Fatalf("the next row took %+v", place)
	}
	drainSettlements(t, service)
	if sequences := storedSequences(t, db); !slices.Equal(sequences, []uint32{1, 2}) {
		t.Fatalf("stored batches %v", sequences)
	}
	var full struct {
		Leaves string `json:"leaves"`
	}
	if err := json.Unmarshal([]byte(db.storedBatches()[0]), &full); err != nil {
		t.Fatal(err)
	}
	if leaves, err := base64.RawURLEncoding.DecodeString(full.Leaves); err != nil || len(leaves) != maxLogBatchLeaves*64 {
		t.Fatalf("the full batch holds %d bytes of leaves: %v", len(leaves), err)
	}
}

// Rows from concurrent requests take distinct places that leave no gap.
func TestConcurrentRowsTakeDistinctPlaces(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	service := db.service
	signer := &countingLogSigner{}
	service.SetLogSigner(signer)
	const callers, rowsEach = 16, 1000
	places := make(chan LogPosition, callers*rowsEach)
	var group sync.WaitGroup
	for range callers {
		group.Go(func() {
			for range rowsEach {
				event := testGatewayRequestEvent()
				event.NodeID = testLogNode
				if _, err := service.encodeSignedRow(&event); err != nil || event.LogBatch == nil {
					t.Errorf("a row took %+v: %v", event.LogBatch, err)
					return
				}
				places <- *event.LogBatch
			}
		})
	}
	group.Wait()
	close(places)
	seen := map[LogPosition]bool{}
	for place := range places {
		if seen[place] {
			t.Fatalf("two rows took %+v", place)
		}
		seen[place] = true
	}
	sealOpenBatch(service, time.Now())
	total := 0
	for _, batch := range signer.sealed() {
		for index := range uint32(batch.leaves) {
			if !seen[LogPosition{batch.sequence, index}] {
				t.Fatalf("batch %d holds a leaf at %d that no row took", batch.sequence, index)
			}
		}
		total += batch.leaves
	}
	if total != callers*rowsEach || len(seen) != total {
		t.Fatalf("%d rows took %d places in batches of %d leaves", callers*rowsEach, len(seen), total)
	}
}

// The worker closes the open batch at the end of each period and stores it, without a full
// batch or a drain.
func TestTheOpenBatchClosesAtTheEndOfItsPeriod(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	service := db.service
	signer := &countingLogSigner{}
	service.SetLogSigner(signer)
	service.logBatches.period = 20 * time.Millisecond
	placeTestRow(t, service)
	waitFor(t, func() bool { return len(db.storedBatches()) == 1 })
	if sealed := signer.sealed(); len(sealed) != 1 || sealed[0].leaves != 1 || sealed[0].sealedAt.Before(sealed[0].openedAt) {
		t.Fatalf("sealed %+v", sealed)
	}
	if place := placeTestRow(t, service); place == nil || *place != (LogPosition{Sequence: 2}) {
		t.Fatalf("the next row took %+v", place)
	}
}

// A batch never closes before it opened, even when the wall clock steps back.
func TestBatchesCloseNoEarlierThanTheyOpened(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	signer := &countingLogSigner{}
	db.service.SetLogSigner(signer)
	placeTestRow(t, db.service)
	sealOpenBatch(db.service, time.Now().Add(-time.Hour))
	if sealed := signer.sealed(); len(sealed) != 1 || !sealed[0].sealedAt.Equal(sealed[0].openedAt) {
		t.Fatalf("sealed %+v", sealed)
	}
}

// A batch that fails to sign is dropped, and the next row opens the next batch, so the
// missing number shows the loss.
func TestABatchThatFailsToSignIsDropped(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	service := db.service
	signer := &countingLogSigner{fail: true}
	service.SetLogSigner(signer)
	placeTestRow(t, service)
	sealOpenBatch(service, time.Now())
	if diagnostics := service.logBatchDiagnostics(); diagnostics.DroppedBatches != 1 || diagnostics.PendingBatches != 0 || diagnostics.LastFailedAt == nil {
		t.Fatalf("diagnostics are %+v", diagnostics)
	}
	signer.mu.Lock()
	signer.fail = false
	signer.mu.Unlock()
	if place := placeTestRow(t, service); place == nil || *place != (LogPosition{Sequence: 2}) {
		t.Fatalf("the next row took %+v", place)
	}
	drainSettlements(t, service)
	if sequences := storedSequences(t, db); !slices.Equal(sequences, []uint32{2}) {
		t.Fatalf("stored batches %v", sequences)
	}
}

// After the last batch number, rows stay unsigned rather than reuse one.
func TestRowsStayUnsignedAfterTheLastBatchNumber(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	service := db.service
	service.SetLogSigner(&countingLogSigner{})
	service.logBatches.sequence = math.MaxUint32 - 1
	for index := range uint32(2) {
		if place := placeTestRow(t, service); place == nil || *place != (LogPosition{Sequence: math.MaxUint32, Index: index}) {
			t.Fatalf("row %d took %+v", index, place)
		}
	}
	sealOpenBatch(service, time.Now())
	if place := placeTestRow(t, service); place != nil {
		t.Fatalf("a row took %+v after the last batch", *place)
	}
}

// The worker retries a batch after a failed call and drops one that the database refuses,
// and diagnostics count each.
func TestBatchesRetryFailedCallsAndDropRefusedOnes(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	service := db.service
	service.SetLogSigner(&countingLogSigner{})
	var calls atomic.Int32
	db.storeAnswer = func(string) settlementReply {
		switch calls.Add(1) {
		case 1:
			return settlementReply{code: "40001"}
		case 2:
			return settlementReply{drop: true}
		case 3:
			return settlementReply{rows: [][2]string{{"stored"}}}
		case 4:
			return settlementReply{rows: [][2]string{{"unknown_boot"}}}
		default:
			return settlementReply{code: "22023"}
		}
	}
	for range 3 {
		placeTestRow(t, service)
		sealOpenBatch(service, time.Now())
	}
	drainSettlements(t, service)
	if sequences := storedSequences(t, db); !slices.Equal(sequences, []uint32{1}) {
		t.Fatalf("stored batches %v", sequences)
	}
	if diagnostics := service.logBatchDiagnostics(); calls.Load() != 5 || diagnostics.StoredBatches != 1 ||
		diagnostics.DroppedBatches != 2 || diagnostics.PendingBatches != 0 || diagnostics.LastFailedAt == nil {
		t.Fatalf("%d calls, diagnostics %+v", calls.Load(), diagnostics)
	}
}

// While the database is unreachable, sealed batches wait up to maxPendingLogBatches. Beyond
// that the oldest one that the worker is not storing is dropped.
func TestPendingBatchesDropTheOldestThatIsNotBeingStored(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	service := db.service
	service.SetLogSigner(&countingLogSigner{})
	release := make(chan struct{})
	var first sync.Once
	db.storeAnswer = func(string) settlementReply {
		first.Do(func() { <-release })
		return settlementReply{rows: [][2]string{{"stored"}}}
	}
	placeTestRow(t, service)
	sealOpenBatch(service, time.Now())
	b := &service.logBatches
	waitFor(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.storing != nil
	})
	for range maxPendingLogBatches {
		placeTestRow(t, service)
		sealOpenBatch(service, time.Now())
	}
	if diagnostics := service.logBatchDiagnostics(); diagnostics.PendingBatches != maxPendingLogBatches || diagnostics.DroppedBatches != 1 {
		t.Fatalf("diagnostics are %+v", diagnostics)
	}
	close(release)
	drainSettlements(t, service)
	want := []uint32{1}
	for sequence := uint32(3); sequence <= maxPendingLogBatches+1; sequence++ {
		want = append(want, sequence)
	}
	if sequences := storedSequences(t, db); !slices.Equal(sequences, want) {
		t.Fatalf("stored batches %v", sequences)
	}
}

// A drain that ends before the database holds the last batches reports its deadline, and
// closing counts each batch that the database never received as dropped.
func TestClosingCountsBatchesThatTheDatabaseNeverHeld(t *testing.T) {
	db := newFakeSettlementDatabase(t, settleAll)
	service := db.service
	service.SetLogSigner(&countingLogSigner{})
	db.storeAnswer = func(string) settlementReply { return settlementReply{code: "40001"} }
	placeTestRow(t, service)
	sealOpenBatch(service, time.Now())
	placeTestRow(t, service)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	// The drain seals the open batch, so two wait.
	if err := service.DrainFinalizations(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the drain returned %v", err)
	}
	service.closeLogBatches()
	if diagnostics := service.logBatchDiagnostics(); diagnostics.DroppedBatches != 2 || diagnostics.PendingBatches != 0 || diagnostics.StoredBatches != 0 {
		t.Fatalf("diagnostics are %+v", diagnostics)
	}
	if place := placeTestRow(t, service); place != nil {
		t.Fatalf("a row took %+v after closing", *place)
	}
}
