package stogashttp

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
	"github.com/maximhq/bifrost/transports/stogas/confidential/channel"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
)

type sessionTestAttester struct {
	calls atomic.Int64
	block <-chan struct{}
}

func (a *sessionTestAttester) Quote(_ context.Context, data [64]byte) ([]byte, error) {
	a.calls.Add(1)
	if a.block != nil {
		<-a.block
	}
	report := make([]byte, 1184)
	binary.LittleEndian.PutUint32(report, 3)
	binary.LittleEndian.PutUint32(report[0x34:], 1)
	copy(report[0x50:0x90], data[:])
	return attest.EncodeEnvelope(attest.Envelope{Provider: attest.ProviderSEVGuest, Report: base64.RawURLEncoding.EncodeToString(report)})
}

type sessionHTTPFixture struct {
	server        *Server
	endpoint      *httptest.Server
	reporter      *sessionTestAttester
	root          []byte
	initialPublic []byte
	id            []byte
	sequence      uint64
}

func newSessionHTTPFixture(t *testing.T, next requestHandler, http2 bool) *sessionHTTPFixture {
	t.Helper()
	f := &sessionHTTPFixture{reporter: new(sessionTestAttester)}
	batcher, err := attest.NewBatcher(f.reporter, func() (func(), bool) { return func() {}, true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = batcher.Close(context.Background()) })
	boot := attest.BootEvidence{Document: []byte(`{"fixture":"HTTP adapter only"}`), Inclusion: []byte(`{}`)}
	setup, err := channel.NewServerSetup(attest.Production, boot, 10*time.Minute, batcher)
	if err != nil {
		t.Fatal(err)
	}
	store, err := channel.NewStore(setup, func() (func(), bool) { return func() {}, true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	f.server = &Server{memory: newRequestMemoryAdmission(), requests: newRequestDrain(), sessions: store, sessionNodeID: "fixture-owner", ipAdmission: newIPAdmission()}
	f.endpoint = httptest.NewUnstartedServer(f.server.ipRequestAdmission(f.server.sessionTransport(next)))
	f.endpoint.EnableHTTP2 = http2
	f.endpoint.StartTLS()
	t.Cleanup(f.endpoint.Close)
	seed, hello := sessionTestHello(t)
	response := f.post(t, hello, false)
	if response.StatusCode != 200 {
		t.Fatalf("setup status %d", response.StatusCode)
	}
	if (response.ProtoMajor == 2) != http2 {
		t.Fatal("fixture used the wrong HTTP version")
	}
	wire, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	const prefixSize = 6 + 32 + 4 + 1120 + 32
	key, err := hpke.MLKEM768X25519().NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	helloHash := sha256.Sum256(hello)
	info := append([]byte("stogas.e2ee.setup.v3\x00"), helloHash[:]...)
	recipient, err := hpke.NewRecipient(wire[42:prefixSize-32], key, hpke.HKDFSHA256(), hpke.ExportOnly(), info)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	hash.Write([]byte("stogas.e2ee.transcript.v3\x00"))
	hash.Write(hello)
	hash.Write(wire[:prefixSize])
	bootHash := sha256.Sum256(boot.Document)
	hash.Write(bootHash[:])
	f.root, err = recipient.Export("stogas.e2ee.root.v3\x00"+string(hash.Sum(nil)), 32)
	if err != nil {
		t.Fatal(err)
	}
	f.id = bytes.Clone(wire[6:38])
	f.initialPublic = bytes.Clone(wire[prefixSize-32 : prefixSize])
	t.Cleanup(func() { clear(f.root) })
	return f
}

func (f *sessionHTTPFixture) post(t *testing.T, wire []byte, owner bool) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, f.endpoint.URL+sessionPath, bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", sessionContentType)
	if owner {
		request.Header.Set(sessionNodeHeader, f.server.sessionNodeID)
	}
	response, err := f.endpoint.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

type sessionTestCipher struct {
	aead          cipher.AEAD
	nonce         [12]byte
	counter       uint64
	header        []byte
	fixture       *sessionHTTPFixture
	requestNumber uint64
}

const testTriple = "stogas.e2ee.triple.v3_X25519_MLKEM768_HKDFSHA256"
const testDouble = "stogas.e2ee.double.v3_X25519_HKDFSHA256:Root"
const testQuantum = "stogas.e2ee.spqr.v3_MLKEM768_HKDFSHA256"

func testHKDF(key, salt []byte, info string, size int) []byte {
	result, err := hkdf.Key(sha256.New, key, salt, info, size)
	if err != nil {
		panic(err)
	}
	return result
}
func testClassicalKey() *ecdh.PrivateKey {
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		panic(err)
	}
	return key
}
func testDH(public []byte) []byte {
	key, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		panic(err)
	}
	shared, err := testClassicalKey().ECDH(key)
	if err != nil {
		panic(err)
	}
	return shared
}
func (f *sessionHTTPFixture) initialChains() ([]byte, []byte) {
	split := testHKDF(f.root, nil, testTriple+":Initialization", 64)
	return testHKDF(testDH(f.initialPublic), split[:32], testDouble, 64), testHKDF(split[32:], nil, testQuantum+":Chain Start", 96)
}
func testMessageSecret(classical, quantum []byte, classicalN, quantumN uint64) []byte {
	var ec, pq []byte
	for i := uint64(0); i <= classicalN; i++ {
		mac := hmac.New(sha256.New, classical)
		mac.Write([]byte{1})
		ec = mac.Sum(nil)
		mac.Reset()
		mac.Write([]byte{2})
		classical = mac.Sum(nil)
	}
	for i := uint64(1); i <= quantumN; i++ {
		info := binary.BigEndian.AppendUint64([]byte(testQuantum+":Chain Step"), i)
		step := testHKDF(quantum, nil, string(info), 64)
		quantum, pq = step[:32], step[32:]
	}
	return testHKDF(ec, pq, testTriple, 32)
}
func (f *sessionHTTPFixture) cipher(t *testing.T, number uint64, direction byte) *sessionTestCipher {
	t.Helper()
	if direction != 1 {
		t.Fatal("client sends requests only")
	}
	ec, pq := f.initialChains()
	secret := testMessageSecret(ec[32:], pq[32:64], number, number+1)
	header := testClassicalKey().PublicKey().Bytes()
	header = binary.BigEndian.AppendUint64(header, 0)
	header = binary.BigEndian.AppendUint64(header, number)
	header = binary.BigEndian.AppendUint64(header, 0)
	header = binary.BigEndian.AppendUint64(header, number+1)
	header = binary.BigEndian.AppendUint64(header, 1)
	header = append(header, 0)
	return f.recordCipher(t, number, direction, secret, header)
}
func (f *sessionHTTPFixture) responseCipher(t *testing.T, number uint64, header []byte) *sessionTestCipher {
	t.Helper()
	if len(header) < 73 {
		t.Fatal("short hybrid header")
	}
	ecN, pqN := binary.BigEndian.Uint64(header[40:48]), binary.BigEndian.Uint64(header[56:64])
	if ecN > 4096 || pqN == 0 || pqN > 4096 || binary.BigEndian.Uint64(header[64:72]) != 1 {
		t.Fatal("invalid hybrid counters")
	}
	ec, pq := f.initialChains()
	next := testHKDF(testDH(header[:32]), ec[:32], testDouble, 64)
	secret := testMessageSecret(next[32:], pq[64:], ecN, pqN)
	return f.recordCipher(t, number, 2, secret, nil)
}
func (f *sessionHTTPFixture) recordCipher(t *testing.T, number uint64, direction byte, secret, header []byte) *sessionTestCipher {
	t.Helper()
	info := append([]byte("stogas.e2ee.record.v3\x00"), f.id...)
	info = binary.BigEndian.AppendUint64(info, number)
	info = append(info, direction)
	material, err := hkdf.Expand(sha256.New, secret, string(info), 44)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(material[:32])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &sessionTestCipher{aead: aead, nonce: [12]byte(material[32:]), header: header}
}
func (c *sessionTestCipher) nextNonce() [12]byte {
	nonce := c.nonce
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], c.counter)
	c.counter++
	for index, value := range count {
		nonce[4+index] ^= value
	}
	return nonce
}
func (c *sessionTestCipher) seal(kind byte, body []byte) []byte {
	nonce := c.nextNonce()
	prefix := make([]byte, 4)
	if c.counter == 1 {
		prefix = binary.BigEndian.AppendUint16(prefix, uint16(len(c.header)))
		prefix = append(prefix, c.header...)
	}
	binary.BigEndian.PutUint32(prefix, uint32(len(prefix)+1+len(body)+16))
	return c.aead.Seal(prefix, nonce[:], append([]byte{kind}, body...), prefix)
}
func (f *sessionHTTPFixture) request(t *testing.T, metadata, body []byte) ([]byte, *sessionTestCipher) {
	number := f.sequence
	f.sequence++
	encoder := f.cipher(t, number, 1)
	wire := append([]byte("STGS\x03\x03"), f.id...)
	wire = binary.BigEndian.AppendUint64(wire, number)
	wire = append(wire, encoder.seal(byte(channel.Metadata), metadata)...)
	for len(body) != 0 {
		n := min(len(body), channel.MaxRecordPlaintext)
		wire = append(wire, encoder.seal(byte(channel.Data), body[:n])...)
		body = body[n:]
	}
	wire = append(wire, encoder.seal(byte(channel.Finished), nil)...)
	return wire, &sessionTestCipher{fixture: f, requestNumber: number}
}
func readSessionResponse(t *testing.T, response *http.Response, decoder *sessionTestCipher) (sessionResponseMetadata, []byte) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != sessionContentType {
		t.Fatalf("outer status %d", response.StatusCode)
	}
	var metadata sessionResponseMetadata
	var body []byte
	finished := false
	for {
		var prefix [4]byte
		_, err := io.ReadFull(response.Body, prefix[:])
		if err == io.EOF {
			break
		}
		if err != nil || finished {
			t.Fatal("invalid response framing", err)
		}
		size, err := channel.RecordSize(prefix[:])
		if err != nil {
			t.Fatal(err)
		}
		encoded := make([]byte, size-4)
		if _, err := io.ReadFull(response.Body, encoded); err != nil {
			t.Fatal(err)
		}
		aad := prefix[:]
		if decoder.counter == 0 {
			if len(encoded) < 2+73+17 {
				t.Fatal("short metadata frame")
			}
			headerEnd := 2 + int(binary.BigEndian.Uint16(encoded[:2]))
			if headerEnd+17 > len(encoded) {
				t.Fatal("invalid ratchet header")
			}
			// Response allocation order is independent of HTTP numbering.
			derived := decoder.fixture.responseCipher(t, decoder.requestNumber, encoded[2:headerEnd])
			decoder.aead, decoder.nonce = derived.aead, derived.nonce
			aad = append(aad, encoded[:headerEnd]...)
			encoded = encoded[headerEnd:]
		}
		nonce := decoder.nextNonce()
		plaintext, err := decoder.aead.Open(nil, nonce[:], encoded, aad)
		if err != nil {
			t.Fatal(err)
		}
		switch channel.Kind(plaintext[0]) {
		case channel.Metadata:
			if metadata.Status != 0 {
				t.Fatal("repeated metadata")
			}
			if err := json.Unmarshal(plaintext[1:], &metadata); err != nil {
				t.Fatal(err)
			}
		case channel.Data:
			body = append(body, plaintext[1:]...)
		case channel.Finished:
			finished = true
		default:
			t.Fatal("unexpected record")
		}
	}
	if !finished || metadata.Status == 0 {
		t.Fatal("unauthenticated completion")
	}
	return metadata, body
}

func TestSessionHTTPStreamingReplayAndClose(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("HTTP2=%t", http2), func(t *testing.T) { testSessionHTTPStreamingReplayAndClose(t, http2) })
	}
}

func testSessionHTTPStreamingReplayAndClose(t *testing.T, http2 bool) {
	var dispatched atomic.Int64
	f := newSessionHTTPFixture(t, func(ctx *requestContext) {
		if ctx.request.Header.Get("Authorization") != "Bearer secret" || ctx.request.URL.Path != "/v1/chat/completions" {
			t.Error("lost encrypted request metadata")
		}
		body, err := io.ReadAll(ctx.request.Body)
		if err != nil {
			ctx.writer.WriteHeader(400)
			return
		}
		dispatched.Add(1)
		ctx.writer.Header().Set("Content-Type", "text/event-stream")
		ctx.writer.Header().Set("X-Secret-Diagnostic", "private")
		ctx.writer.WriteHeader(201)
		_, _ = ctx.writer.Write(body[:len(body)/2])
		_ = http.NewResponseController(ctx.writer).Flush()
		_, _ = ctx.writer.Write(body[len(body)/2:])
	}, http2)
	body := bytes.Repeat([]byte("secret body"), 15000)
	wire, decoder := f.request(t, []byte(`{"method":"POST","path":"/v1/chat/completions","headers":{"Authorization":"Bearer secret","Content-Type":"application/json"}}`), body)
	response := f.post(t, wire, true)
	if response.Header.Get("X-Secret-Diagnostic") != "" {
		t.Fatal("leaked inner header")
	}
	metadata, actual := readSessionResponse(t, response, decoder)
	if metadata.Status != 201 || !bytes.Equal(actual, body) {
		t.Fatal("response changed")
	}
	response = f.post(t, wire, true)
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 400 || dispatched.Load() != 1 {
		t.Fatal("duplicate dispatched or created response state")
	}
	wire, decoder = f.request(t, []byte(`{"method":"DELETE","path":"/v1/session","headers":{}}`), nil)
	metadata, _ = readSessionResponse(t, f.post(t, wire, true), decoder)
	if metadata.Status != 204 || f.server.sessions.Diagnostics().Open != 0 {
		t.Fatal("close did not retire session")
	}
	if got := f.server.memory.reserved.Load(); got != 0 {
		t.Fatalf("retained HTTP memory: %d", got)
	}
	if limits := f.server.ipAdmission.diagnostics(); limits.Setup.Attempts != 1 || limits.Request.Attempts != 4 {
		t.Fatalf("session reuse or close was counted as setup, or inner request counted twice: %#v", limits)
	}
}

func TestSessionHTTPRejectsBodyBeforeDispatchAndAllowsCloseDuringDrain(t *testing.T) {
	var dispatched atomic.Int64
	f := newSessionHTTPFixture(t, func(ctx *requestContext) {
		if _, err := io.ReadAll(ctx.request.Body); err != nil {
			ctx.writer.WriteHeader(400)
			return
		}
		dispatched.Add(1)
		ctx.writer.WriteHeader(204)
	}, true)
	metadata := []byte(`{"method":"POST","path":"/v1/responses","headers":{}}`)
	for _, mutate := range []func([]byte) []byte{
		func(wire []byte) []byte { return wire[:len(wire)-1] },
		func(wire []byte) []byte { wire[len(wire)-1] ^= 1; return wire },
		func(wire []byte) []byte { return append(wire, 0) },
	} {
		wire, decoder := f.request(t, metadata, []byte("body"))
		result, _ := readSessionResponse(t, f.post(t, mutate(wire), true), decoder)
		if result.Status != 400 {
			t.Fatal("accepted invalid body")
		}
	}
	if dispatched.Load() != 0 {
		t.Fatal("invalid input reached dispatch")
	}
	f.server.requests.start()
	wire, decoder := f.request(t, metadata, nil)
	result, _ := readSessionResponse(t, f.post(t, wire, true), decoder)
	if result.Status != 503 || dispatched.Load() != 0 {
		t.Fatal("draining admitted work")
	}
	wire, decoder = f.request(t, []byte(`{"method":"DELETE","path":"/v1/session","headers":{}}`), nil)
	result, _ = readSessionResponse(t, f.post(t, wire, true), decoder)
	if result.Status != 204 {
		t.Fatal("draining prevented authenticated cleanup")
	}
}

func TestSessionHTTPMetadataAndOuterRoutingCannotGrantAuthority(t *testing.T) {
	var dispatched atomic.Int64
	f := newSessionHTTPFixture(t, func(ctx *requestContext) {
		dispatched.Add(1)
		ctx.writer.WriteHeader(204)
	}, true)
	for _, metadata := range []string{
		`{"method":"POST","path":"https://elsewhere.example/v1/responses","headers":{}}`,
		`{"method":"POST","path":"/v1/responses?x=1","headers":{}}`,
		`{"method":"POST","path":"/v1/responses","extra":true,"headers":{}}`,
		`{"method":"POST","path":"/v1/responses","headers":{"X-Test":"ok\r\nInjected: true"}}`,
		`{"method":"POST","path":"/v1/responses","headers":{"Authorization":"one","authorization":"two"}}`,
		`{"method":"POST","path":"/v1/responses","headers":{"Content-Length":"0"}}`,
		`{"method":"POST","path":"/v1/responses","headers":{"Forwarded":"for=somebody"}}`,
		`{"method":"GET","path":"/diagnostics/v1","headers":{}}`,
	} {
		wire, decoder := f.request(t, []byte(metadata), nil)
		result, _ := readSessionResponse(t, f.post(t, wire, true), decoder)
		if result.Status != 400 {
			t.Fatalf("accepted metadata %s", metadata)
		}
	}
	wire, decoder := f.request(t, []byte(`{"method":"DELETE","path":"/v1/session","headers":{}}`), nil)
	response := f.post(t, wire, false)
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 421 || f.server.sessions.Diagnostics().Open != 1 {
		t.Fatal("unauthenticated routing closed a session")
	}
	// The rejected outer selector never consumed the authenticated request number.
	metadata, _ := readSessionResponse(t, f.post(t, wire, true), decoder)
	if metadata.Status != 204 || dispatched.Load() != 0 {
		t.Fatal("invalid request reached application")
	}
}

func TestSessionHTTPTransportMemoryOutlivesApplicationFinalization(t *testing.T) {
	var server *Server
	f := newSessionHTTPFixture(t, func(ctx *requestContext) {
		if _, err := io.ReadAll(ctx.request.Body); err != nil {
			t.Error(err)
			return
		}
		if got := server.memory.reserved.Load(); got != minimumRequestWeightBytes {
			t.Errorf("duplicated initial reservation: %d", got)
		}
		ctx.memory.release()
		if got := server.memory.reserved.Load(); got != int64(sessionAdapterRetainedBytes) {
			t.Errorf("released live encryption buffers: %d", got)
		}
		ctx.writer.WriteHeader(204)
	}, true)
	server = f.server
	wire, decoder := f.request(t, []byte(`{"method":"POST","path":"/v1/responses","headers":{}}`), nil)
	metadata, _ := readSessionResponse(t, f.post(t, wire, true), decoder)
	if metadata.Status != 204 || f.server.memory.reserved.Load() != 0 {
		t.Fatal("transport did not release after its final write")
	}
}

func sessionTestHello(t *testing.T) ([]byte, []byte) {
	t.Helper()
	encoded, err := os.ReadFile("../stogas/confidential/channel/testdata/setup-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Seed  string `json:"seed_hex"`
		Hello string `json:"hello_hex"`
	}
	if err := json.Unmarshal(encoded, &vector); err != nil {
		t.Fatal(err)
	}
	hello, _ := hex.DecodeString(vector.Hello)
	seed, _ := hex.DecodeString(vector.Seed)
	return seed, hello
}

type delayedSessionInput struct {
	io.Reader
	delayed bool
}

func (r *delayedSessionInput) Read(output []byte) (int, error) {
	if !r.delayed {
		r.delayed = true
		time.Sleep(7 * time.Second)
	}
	return r.Reader.Read(output)
}

type sessionDeadlineRecorder struct{ *httptest.ResponseRecorder }

func (*sessionDeadlineRecorder) SetReadDeadline(time.Time) error  { return nil }
func (*sessionDeadlineRecorder) SetWriteDeadline(time.Time) error { return nil }

func TestSessionSetupAdmissionTracksRetainedCapacityBeforeHardwareWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		memory := &requestMemoryAdmission{budget: minimumRequestWeightBytes + 2*encryptedSessionRetainedBytes + quoteRetainedBytes}
		reporter := new(sessionTestAttester)
		batcher, err := attest.NewBatcher(reporter, memory.confidentialReservation(quoteRetainedBytes))
		if err != nil {
			t.Fatal(err)
		}
		defer batcher.Close(context.Background())
		setup, err := channel.NewServerSetup(attest.Production, attest.BootEvidence{Document: []byte(`{}`), Inclusion: []byte(`{}`)}, time.Minute, batcher)
		if err != nil {
			t.Fatal(err)
		}
		store, err := channel.NewStore(setup, memory.confidentialReservation(encryptedSessionRetainedBytes))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		server := &Server{memory: memory, sessions: store, ipAdmission: newIPAdmission()}
		_, hello := sessionTestHello(t)
		open := func() *httptest.ResponseRecorder {
			request := httptest.NewRequest(http.MethodPost, sessionPath, bytes.NewReader(hello))
			request.Header.Set("Content-Type", sessionContentType)
			writer := &sessionDeadlineRecorder{httptest.NewRecorder()}
			server.sessionTransport(func(*requestContext) { t.Fatal("setup reached inference") }).ServeHTTP(writer, request)
			synctest.Wait()
			return writer.ResponseRecorder
		}
		for range ipSetupBurst {
			_, _ = server.ipAdmission.allow("192.0.2.1:1234", true, time.Now())
		}
		if rejected := open(); rejected.Code != http.StatusTooManyRequests || rejected.Header().Get("Retry-After") != "1" || reporter.calls.Load() != 0 || memory.reserved.Load() != 0 {
			t.Fatal("IP setup rejection spent hardware work or retained memory")
		}
		time.Sleep(ipFullRefillInterval)
		first := open()
		if first.Code != http.StatusOK || open().Code != http.StatusOK {
			t.Fatal("available session capacity was rejected")
		}
		if open().Code != http.StatusServiceUnavailable || reporter.calls.Load() != 2 || memory.reserved.Load() != 2*encryptedSessionRetainedBytes {
			t.Fatal("full capacity spent hardware work or leaked a partial setup")
		}
		var id [32]byte
		copy(id[:], first.Body.Bytes()[6:38])
		store.Remove(id)
		if open().Code != http.StatusOK || reporter.calls.Load() != 3 {
			t.Fatal("freed capacity did not admit immediately")
		}
		store.Close()
		if memory.reserved.Load() != 0 {
			t.Fatal("session cleanup left a reservation")
		}
	})
}

func TestSessionHTTPSetupDeadlineIncludesUploadAndStalledQuote(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		blocked := make(chan struct{})
		reporter := &sessionTestAttester{block: blocked}
		var quoteBytes atomic.Int64
		batcher, err := attest.NewBatcher(reporter, func() (func(), bool) { quoteBytes.Add(1); return func() { quoteBytes.Add(-1) }, true })
		if err != nil {
			t.Fatal(err)
		}
		defer func() { close(blocked); _ = batcher.Close(context.Background()) }()
		setup, err := channel.NewServerSetup(attest.Production, attest.BootEvidence{Document: []byte(`{}`), Inclusion: []byte(`{}`)}, time.Minute, batcher)
		if err != nil {
			t.Fatal(err)
		}
		store, err := channel.NewStore(setup, func() (func(), bool) { return func() {}, true })
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		server := &Server{memory: newRequestMemoryAdmission(), sessions: store}
		_, hello := sessionTestHello(t)
		request := httptest.NewRequest(http.MethodPost, sessionPath, &delayedSessionInput{Reader: bytes.NewReader(hello)})
		request.Header.Set("Content-Type", sessionContentType)
		writer := &sessionDeadlineRecorder{httptest.NewRecorder()}
		started := time.Now()
		server.sessionTransport(func(*requestContext) { t.Fatal("setup reached application") }).ServeHTTP(writer, request)
		if elapsed := time.Since(started); elapsed != sessionSetupBudget {
			t.Fatalf("setup budget reset after prefix: %s", elapsed)
		}
		if writer.Code != 503 || store.Diagnostics().Open != 0 || server.memory.reserved.Load() != 0 {
			t.Fatal("expired setup kept HTTP/session state")
		}
		if reporter.calls.Load() != 1 || quoteBytes.Load() != 1 {
			t.Fatal("dispatched hardware work lost its reservation before returning")
		}
	})
}

func TestSessionHTTPBufferedMetadataReceiptsAndOuterQueryRejection(t *testing.T) {
	service, publicKey, boot := testProofService(t)
	var calls atomic.Int32
	f := newSessionHTTPFixture(t, func(ctx *requestContext) {
		calls.Add(1)
		if !ctx.encrypted || ctx.request.Header.Get("Authorization") != "Bearer secret" {
			t.Error("encrypted credential context lost")
		}
		ctx.body, _ = io.ReadAll(ctx.request.Body)
		resolution := mustResolvedRequest(t, "/v1/chat/completions", string(ctx.body))
		bifrostCtx, state, cancel, err := newRequestContext(ctx, resolution, apiCredential{Raw: "secret"}, stogas.DefaultAdapter{}, "")
		if err != nil {
			t.Error(err)
			ctx.writer.WriteHeader(500)
			return
		}
		defer cancel()
		if !wantsReceipt(bifrostCtx) || !state.SingleUseRequestID || state.RequestID == "client-chosen" {
			t.Error("request identity or metadata selection lost")
		}
		state.FinalEvent = &billing.RequestEvent{CreatedAt: "2026-08-24T12:34:56.789Z", BilledCostUSD: "0", UpstreamCostUSD: "0", Meters: billing.EventMeters{}}
		ctx.writer.Header().Set("Retry-After", "1")
		ctx.writer.Header().Set("X-Internal-Note", "private")
		(&Server{proofs: service}).writeInferenceJSON(ctx, bifrostCtx, state, 429, map[string]any{"error": "limited"})
	}, true)
	body := []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}]}`)
	metadata, _ := json.Marshal(sessionRequestMetadata{Method: "POST", Path: "/v1/chat/completions", Headers: map[string]string{"Authorization": "Bearer secret", "Content-Type": "application/json", "Stogas-Metadata": "v1", "X-Request-ID": "client-chosen"}})
	wire, decoder := f.request(t, metadata, body)
	request, err := http.NewRequest(http.MethodPost, f.endpoint.URL+sessionPath+"?unbound=true", bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", sessionContentType)
	request.Header.Set(sessionNodeHeader, f.server.sessionNodeID)
	response, err := f.endpoint.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 400 || calls.Load() != 0 {
		t.Fatal("outer query reached plaintext handler")
	}
	response = f.post(t, wire, true)
	if response.StatusCode != 200 || response.Header.Get("Retry-After") != "" || response.Header.Get("X-Internal-Note") != "" {
		t.Fatal("inner status/header escaped encryption")
	}
	inner, plain := readSessionResponse(t, response, decoder)
	var result struct {
		Receipt proof.Object `json:"stogas"`
	}
	if err = json.Unmarshal(plain, &result); err != nil {
		t.Fatal(err)
	}
	if inner.Status != 429 || inner.Headers["Retry-After"] != "1" {
		t.Fatal("lost inner status or retry guidance", inner)
	}
	if !proof.VerifyReceipt(publicKey, result.Receipt.Receipt, boot, sha256.Sum256(body), sha256.Sum256([]byte(`{"error":"limited"}`)), result.Receipt) {
		t.Fatal("binary E2EE receipt does not cover original content")
	}
}
