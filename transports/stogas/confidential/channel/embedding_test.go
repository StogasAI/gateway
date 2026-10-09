package channel

// Exercises the Rust embedding through the verifier Go package directly, with an
// independent Go client. The ServerSession tests above cover the gateway wrapper.
import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	verifier "github.com/StogasAI/verifier/go"
	ref "github.com/StogasAI/verifier/go/reference"
)

// establishChannel runs the production setup entry point against an independent
// Go HPKE client. Sessions never start from caller-supplied keys.
func establishChannel(t *testing.T, environment byte) (*verifier.ChannelSession, *ref.Session) {
	t.Helper()
	client, err := ref.NewSetup(environment, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	bootHash := sha256.Sum256([]byte("synthetic boot document"))
	prepared, err := verifier.PrepareChannelSetup(environment, 600, bootHash, client.Hello)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(prepared.Session.Close)
	setup, err := client.Complete(prepared.ResponsePrefix, bootHash)
	if err != nil {
		t.Fatal(err)
	}
	if setup.ID != prepared.ID || setup.Transcript != prepared.Transcript || setup.IdleSeconds != 600 {
		t.Fatal("quote transcript omitted or changed a setup field")
	}
	return prepared.Session, setup
}

func TestEmbeddedSetupInteroperatesWithIndependentHPKEAndRatchet(t *testing.T) {
	testPreparedSetup(t, 1)
}

// Gateway builds include both environments; each setup selects one explicitly.
func TestEmbeddedSetupUsesCompiledStagingEnvironment(t *testing.T) {
	testPreparedSetup(t, 2)
}

func testPreparedSetup(t *testing.T, environment byte) {
	t.Helper()
	session, setup := establishChannel(t, environment)
	message := setup.Client().Send(0, bytes.Repeat([]byte{17}, 32), bytes.Repeat([]byte{19}, 32))
	encoded := ref.SealRecord(message.Secret, setup.ID[:], 0, 1, 0, message.Header, 1, []byte("credentials"))
	reader, writer, metadata, err := session.AcceptStart(0, encoded)
	if err != nil || string(metadata) != "credentials" {
		t.Fatalf("setup did not establish matching ratchet state: %v", err)
	}
	reader.Close()
	writer.Close()
	session.Close()
	if _, _, _, err := session.AcceptStart(1, encoded); !errors.Is(err, verifier.ErrClosed) {
		t.Fatal("closed setup session accepted a request")
	}
}

type channelRecord struct {
	kind    byte
	content []byte
}

func sealRequest(message ref.Message, id [32]byte, records []channelRecord) [][]byte {
	encoded := make([][]byte, len(records))
	for i, record := range records {
		encoded[i] = ref.SealRecord(message.Secret, id[:], message.Request, 1, uint64(i), message.Header, record.kind, record.content)
	}
	return encoded
}

func TestChannelForgedGapDoesNotConsumeSessionState(t *testing.T) {
	session, setup := establishChannel(t, 1)
	client := setup.Client()
	first := client.Send(0, bytes.Repeat([]byte{17}, 32), bytes.Repeat([]byte{19}, 32))
	message := first
	for request := range uint64(255) {
		message = client.Send(request+1, nil, nil)
	}
	forged := ref.SealRecord(message.Secret, setup.ID[:], 255, 1, 0, message.Header, 1, []byte("credentials"))
	forged[len(forged)-1] ^= 1
	if _, _, _, err := session.AcceptStart(255, forged); !errors.Is(err, verifier.ErrChannelAuthentication) {
		t.Fatalf("forged body accepted: %v", err)
	}
	reader, writer, metadata, err := session.AcceptStart(0, sealRequest(first, setup.ID, []channelRecord{{1, []byte("credentials")}})[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	t.Cleanup(writer.Close)
	if string(metadata) != "credentials" {
		t.Fatal("rejected starts changed the authenticated metadata")
	}
}

func TestChannelConcurrentOwnersAndCloseUseTheRustCore(t *testing.T) {
	session, setup := establishChannel(t, 1)
	client := setup.Client()
	message := client.Send(0, bytes.Repeat([]byte{17}, 32), bytes.Repeat([]byte{19}, 32))
	request := []channelRecord{{1, []byte("credentials")}, {2, []byte("request body")}, {3, nil}}
	response := []channelRecord{{4, nil}, {1, []byte("status=200")}, {2, []byte("response body")}, {3, nil}}
	encoded := sealRequest(message, setup.ID, request)
	forged := bytes.Clone(encoded[0])
	forged[len(forged)-1] ^= 1
	if _, _, _, err := session.AcceptStart(0, forged); !errors.Is(err, verifier.ErrChannelAuthentication) {
		t.Fatal(err)
	}
	reader, writer, metadata, err := session.AcceptStart(0, bytes.Clone(encoded[0]))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	t.Cleanup(writer.Close)
	if !bytes.Equal(metadata, request[0].content) {
		t.Fatal("wrong metadata")
	}
	if _, _, _, err := session.AcceptStart(0, bytes.Clone(encoded[0])); !errors.Is(err, verifier.ErrChannelRecord) {
		t.Fatal(err)
	}
	// Closing the parent concurrently with independent upload/response work must
	// not destroy admitted keys or let a new start through.
	var wait sync.WaitGroup
	wait.Add(3)
	go func() {
		defer wait.Done()
		for i, record := range request[1:] {
			kind, actual, err := reader.Open(encoded[i+1])
			if err != nil || kind != record.kind || !bytes.Equal(actual, record.content) {
				t.Error("open", err)
			}
		}
		if err := reader.Complete(); err != nil {
			t.Error(err)
		}
	}()
	go func() {
		defer wait.Done()
		// Independent Go decryption of fresh Rust response keys and headers.
		var keys *ref.RecordKeys
		for i, record := range response {
			actual, err := writer.Seal(record.kind, record.content)
			if err != nil {
				t.Error("seal", err)
				return
			}
			prefix := 4
			if i == 0 {
				prefix = 6 + int(binary.BigEndian.Uint16(actual[4:6]))
				keys = ref.NewRecordKeys(client.Receive(ref.Message{Header: actual[6:prefix], Request: 0}), setup.ID[:], 0, 2)
			}
			aead, recordNonce := keys.Next()
			plain, err := aead.Open(nil, recordNonce[:], actual[prefix:], actual[:prefix])
			if err != nil || !bytes.Equal(plain, append([]byte{record.kind}, record.content...)) {
				t.Error("independent response decryption", err)
			}
		}
	}()
	go func() { defer wait.Done(); session.Expire(time.Now()); session.Close(); session.Close() }()
	wait.Wait()
	if _, _, _, err := session.AcceptStart(0, encoded[0]); !errors.Is(err, verifier.ErrClosed) {
		t.Fatal(err)
	}
	reader.Close()
	reader.Close()
	writer.Close()
	writer.Close()
	if _, _, err := reader.Open(nil); !errors.Is(err, verifier.ErrClosed) {
		t.Fatal(err)
	}
	if err := reader.Complete(); !errors.Is(err, verifier.ErrClosed) {
		t.Fatal(err)
	}
	if _, err := writer.Seal(1, nil); !errors.Is(err, verifier.ErrClosed) {
		t.Fatal(err)
	}
}

func TestChannelMalformedInputsDoNotExposePlaintextOrReuseFailedWriters(t *testing.T) {
	session, setup := establishChannel(t, 1)
	message := setup.Client().Send(0, bytes.Repeat([]byte{17}, 32), bytes.Repeat([]byte{19}, 32))
	for _, input := range [][]byte{nil, {}, {0, 0, 0, 0}, make([]byte, 65537)} {
		if reader, writer, plain, err := session.AcceptStart(0, input); err == nil || reader != nil || writer != nil || plain != nil {
			t.Fatal("invalid start", err)
		}
	}
	reader, writer, _, err := session.AcceptStart(0, sealRequest(message, setup.ID, []channelRecord{{1, []byte("credentials")}})[0])
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if _, err := writer.Seal(255, nil); !errors.Is(err, verifier.ErrChannelRecord) {
		t.Fatal(err)
	}
	if _, err := writer.Seal(1, nil); !errors.Is(err, verifier.ErrClosed) {
		t.Fatal(err)
	}
	if _, plain, err := reader.Open(nil); err == nil || plain != nil {
		t.Fatal("invalid body", err)
	}
	if err := reader.Complete(); err == nil {
		t.Fatal("accepted missing terminal record")
	}
}
