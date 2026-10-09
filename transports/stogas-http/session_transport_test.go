package stogashttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	ref "github.com/StogasAI/verifier/go/reference"
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
	delay time.Duration
}

func (a *sessionTestAttester) Quote(_ context.Context, data [64]byte) ([]byte, error) {
	a.calls.Add(1)
	if a.block != nil {
		<-a.block
	}
	if a.delay > 0 {
		time.Sleep(a.delay)
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
	encoder       *ref.Peer
}

func newSessionHTTPFixture(t *testing.T, next requestHandler, http2 bool) *sessionHTTPFixture {
	return newSessionHTTPFixtureWithReporter(t, next, http2, new(sessionTestAttester))
}

func newSessionHTTPFixtureWithReporter(t *testing.T, next requestHandler, http2 bool, reporter *sessionTestAttester) *sessionHTTPFixture {
	t.Helper()
	f := &sessionHTTPFixture{reporter: reporter}
	memory := newRequestMemoryAdmission()
	if err := memory.protectRequestMemory(128 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	batcher, err := attest.NewBatcher(f.reporter, memory.confidentialReservation(quoteRetainedBytes))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = batcher.Close(context.Background()) })
	boot := attest.BootEvidence{Document: []byte(`{"fixture":"HTTP adapter only"}`), Inclusion: []byte(`{}`)}
	setup, err := channel.NewServerSetup(attest.Production, boot, 10*time.Minute, batcher)
	if err != nil {
		t.Fatal(err)
	}
	store, err := channel.NewStore(setup, memory.confidentialReservation(encryptedSessionRetainedBytes))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	f.server = &Server{memory: memory, requests: newRequestDrain(), sessions: store, sessionNodeID: "fixture-owner", ipAdmission: newIPAdmission()}
	memory.reclaim = f.server.reclaimIdleMemory
	f.endpoint = httptest.NewUnstartedServer(f.server.ipRequestAdmission(f.server.sessionTransport(next)))
	f.endpoint.Config.ConnContext = withHTTPConnection
	f.endpoint.Config.ConnState = f.server.idleConnections.observe
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
	f.root, f.initialPublic = sessionTestSetupKeys(t, seed, hello, wire, boot.Document)
	f.id = bytes.Clone(wire[6:38])
	f.encoder = f.referenceClient()
	t.Cleanup(func() { clear(f.root) })
	return f
}

func sessionTestSetupKeys(t testing.TB, seed, hello, wire, boot []byte) ([]byte, []byte) {
	t.Helper()
	const prefixSize = 6 + 32 + 4 + 1120 + ref.PublicBytes
	if len(wire) < prefixSize {
		t.Fatal("short setup response")
	}
	key, err := hpke.MLKEM768X25519().NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	helloHash := sha256.Sum256(hello)
	info := append([]byte("stogas.e2ee.setup.v1\x00"), helloHash[:]...)
	recipient, err := hpke.NewRecipient(wire[42:prefixSize-ref.PublicBytes], key, hpke.HKDFSHA256(), hpke.ExportOnly(), info)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	hash.Write([]byte("stogas.e2ee.transcript.v1\x00"))
	hash.Write(hello)
	hash.Write(wire[:prefixSize])
	bootHash := sha256.Sum256(boot)
	hash.Write(bootHash[:])
	root, err := recipient.Export("stogas.e2ee.root.v1\x00"+string(hash.Sum(nil)), 32)
	if err != nil {
		t.Fatal(err)
	}
	return root, bytes.Clone(wire[prefixSize-ref.PublicBytes : prefixSize])

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
	keys          *ref.RecordKeys
	counter       uint64
	header        []byte
	fixture       *sessionHTTPFixture
	requestNumber uint64
}

func (f *sessionHTTPFixture) referenceClient() *ref.Peer {
	return ref.New(f.root, &ref.Keys{Public: [ref.PublicBytes]byte(f.initialPublic)}, true)
}
func (f *sessionHTTPFixture) cipher(t *testing.T, number uint64, direction byte) *sessionTestCipher {
	t.Helper()
	if direction != 1 {
		t.Fatal("client sends requests only")
	}
	if f.encoder.Sent != number {
		t.Fatal("unordered fixture request")
	}
	message := f.encoder.Send(number, bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32))
	return f.recordCipher(t, number, direction, message.Secret, message.Header)
}
func (f *sessionHTTPFixture) responseCipher(t *testing.T, number uint64, header []byte) *sessionTestCipher {
	t.Helper()
	peer := f.referenceClient()
	peer.Send(0, bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32))
	return f.recordCipher(t, number, 2, peer.Receive(ref.Message{Header: header, Request: number}), nil)
}
func (f *sessionHTTPFixture) recordCipher(t *testing.T, number uint64, direction byte, secret, header []byte) *sessionTestCipher {
	t.Helper()
	return &sessionTestCipher{keys: ref.NewRecordKeys(secret, f.id, number, direction), header: header}
}
func (c *sessionTestCipher) seal(kind byte, body []byte) []byte {
	aead, nonce := c.keys.Next()
	c.counter++
	prefix := make([]byte, 4)
	if c.counter == 1 {
		prefix = binary.BigEndian.AppendUint16(prefix, uint16(len(c.header)))
		prefix = append(prefix, c.header...)
	}
	binary.BigEndian.PutUint32(prefix, uint32(len(prefix)+1+len(body)+16))
	return aead.Seal(prefix, nonce[:], append([]byte{kind}, body...), prefix)
}
func (f *sessionHTTPFixture) request(t *testing.T, metadata, body []byte) ([]byte, *sessionTestCipher) {
	return f.requestWithRecordSize(t, metadata, body, channel.MaxRecordPlaintext)
}

func (f *sessionHTTPFixture) requestWithRecordSize(t *testing.T, metadata, body []byte, recordSize int) ([]byte, *sessionTestCipher) {
	number := f.sequence
	f.sequence++
	encoder := f.cipher(t, number, 1)
	records := (len(body) + recordSize - 1) / recordSize
	wire := make([]byte, 0, channel.RequestPrefixBytes+len(metadata)+len(body)+(records+2)*channel.RecordOverhead+2+len(encoder.header))
	wire = append(wire, []byte("STGS\x01\x03")...)
	wire = append(wire, f.id...)
	wire = binary.BigEndian.AppendUint64(wire, number)
	wire = append(wire, encoder.seal(byte(channel.Metadata), metadata)...)
	for len(body) != 0 {
		n := min(len(body), recordSize)
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
		kind, plaintext, err := readSessionRecord(t, response.Body, decoder)
		if err == io.EOF {
			break
		}
		if err != nil || finished {
			t.Fatal("invalid response framing", err)
		}
		switch kind {
		case channel.Metadata:
			if metadata.Status != 0 {
				t.Fatal("repeated metadata")
			}
			if err := json.Unmarshal(plaintext, &metadata); err != nil {
				t.Fatal(err)
			}
		case channel.Data:
			if metadata.Status == 0 {
				t.Fatal("body before metadata")
			}
			body = append(body, plaintext...)
		case channel.Keepalive:
			if len(plaintext) != 0 {
				t.Fatal("nonempty keepalive")
			}
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

func readSessionRecord(t *testing.T, input io.Reader, decoder *sessionTestCipher) (channel.Kind, []byte, error) {
	t.Helper()
	var prefix [4]byte
	if _, err := io.ReadFull(input, prefix[:]); err != nil {
		return 0, nil, err
	}
	size, err := channel.RecordSize(prefix[:])
	if err != nil {
		t.Fatal(err)
	}
	encoded := make([]byte, size-4)
	if _, err := io.ReadFull(input, encoded); err != nil {
		return 0, nil, err
	}
	aad := prefix[:]
	if decoder.counter == 0 {
		if len(encoded) < 2+ref.HeaderBytes+17 {
			t.Fatal("short first response frame")
		}
		headerEnd := 2 + int(binary.BigEndian.Uint16(encoded[:2]))
		if headerEnd+17 > len(encoded) {
			t.Fatal("invalid ratchet header")
		}
		// Response allocation order is independent of HTTP numbering.
		derived := decoder.fixture.responseCipher(t, decoder.requestNumber, encoded[2:headerEnd])
		decoder.keys = derived.keys
		aad = append(aad, encoded[:headerEnd]...)
		encoded = encoded[headerEnd:]
	}
	aead, nonce := decoder.keys.Next()
	decoder.counter++
	plaintext, err := aead.Open(nil, nonce[:], encoded, aad)
	if err != nil || len(plaintext) == 0 {
		t.Fatal("invalid encrypted record", err)
	}
	return channel.Kind(plaintext[0]), plaintext[1:], nil
}

func TestSessionHTTPAcknowledgesBeforeUploadAndPreservesLaterStatus(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("HTTP2=%t", http2), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			uploaded := make(chan struct{})
			respond := make(chan struct{})
			addresses := make(chan string, 2)
			var dispatched atomic.Int64
			body := bytes.Repeat([]byte("encrypted upload"), 4096)
			f := newSessionHTTPFixture(t, func(request *requestContext) {
				actual, err := io.ReadAll(request.request.Body)
				if err != nil || !bytes.Equal(actual, body) {
					t.Error("upload failed after receipt", err)
					return
				}
				addresses <- request.request.RemoteAddr
				if dispatched.Add(1) == 1 {
					close(uploaded)
					select {
					case <-respond:
					case <-request.request.Context().Done():
						return
					}
				}
				request.writer.Header().Set("Retry-After", "7")
				request.writer.WriteHeader(http.StatusTooManyRequests)
				_, _ = request.writer.Write([]byte("later rejection"))
			}, http2)
			metadata := []byte(`{"method":"POST","path":"/v1/responses","headers":{}}`)
			wire, decoder := f.request(t, metadata, body)
			firstEnd := channel.RequestPrefixBytes + int(binary.BigEndian.Uint32(wire[channel.RequestPrefixBytes:]))
			input, output := io.Pipe()
			defer input.Close()
			defer output.Close()
			continueUpload := make(chan struct{})
			written := make(chan error, 1)
			go func() {
				_, err := output.Write(wire[:firstEnd])
				if err == nil {
					select {
					case <-continueUpload:
						_, err = output.Write(wire[firstEnd:])
					case <-ctx.Done():
						err = ctx.Err()
					}
				}
				_ = output.CloseWithError(err)
				written <- err
			}()
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint.URL+sessionPath, input)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", sessionContentType)
			request.Header.Set(sessionNodeHeader, f.server.sessionNodeID)
			response, err := f.endpoint.Client().Do(request)
			if err != nil {
				t.Fatal("receipt waited for upload", err)
			}
			defer response.Body.Close()
			kind, payload, err := readSessionRecord(t, response.Body, decoder)
			if err != nil || kind != channel.Keepalive || len(payload) != 0 {
				t.Fatalf("first response was not an authenticated receipt: %v %v", kind, err)
			}
			if response.Close {
				t.Fatal("receipt disabled connection reuse")
			}
			close(continueUpload)
			select {
			case <-uploaded:
			case <-ctx.Done():
				t.Fatal("upload stalled after receipt")
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			close(respond)
			result, actual := readSessionResponse(t, response, decoder)
			if result.Status != http.StatusTooManyRequests || result.Headers["Retry-After"] != "7" || string(actual) != "later rejection" {
				t.Fatalf("receipt changed subsequent response: %#v %q", result, actual)
			}
			wire, decoder = f.request(t, metadata, body)
			readSessionResponse(t, f.post(t, wire, true), decoder)
			if <-addresses != <-addresses {
				t.Fatal("completed request did not reuse its HTTPS connection")
			}
		})
	}
}

func TestSessionHTTPEarlyErrorClosesAbandonedHTTP1Upload(t *testing.T) {
	f := newSessionHTTPFixture(t, func(ctx *requestContext) {
		ctx.writer.WriteHeader(http.StatusTooManyRequests)
	}, false)
	wire, decoder := f.request(t, []byte(`{"method":"POST","path":"/v1/responses","headers":{}}`), nil)
	firstEnd := channel.RequestPrefixBytes + int(binary.BigEndian.Uint32(wire[channel.RequestPrefixBytes:]))
	connection, err := tls.Dial("tcp", f.endpoint.Listener.Addr().String(), f.endpoint.Client().Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(connection, "POST %s HTTP/1.1\r\nHost: fixture\r\nContent-Type: %s\r\n%s: %s\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n", sessionPath, sessionContentType, sessionNodeHeader, f.server.sessionNodeID, firstEnd); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(append(wire[:firstEnd:firstEnd], '\r', '\n')); err != nil {
		t.Fatal(err)
	}
	input := bufio.NewReader(connection)
	response, err := http.ReadResponse(input, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	metadata, _ := readSessionResponse(t, response, decoder)
	if metadata.Status != http.StatusTooManyRequests {
		t.Fatal("lost authenticated error")
	}
	if _, err := input.ReadByte(); err != io.EOF {
		t.Fatal("server retained the abandoned upload after its response", err)
	}
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

func TestSessionHTTPEarlyErrorDoesNotWaitForUpload(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("HTTP2=%t", http2), func(t *testing.T) {
			var status atomic.Int64
			f := newSessionHTTPFixture(t, func(ctx *requestContext) {
				ctx.writer.WriteHeader(int(status.Load()))
			}, http2)
			// Consecutive authenticated errors must not wait for a full ciphertext
			// buffer or the unfinished upload, and must leave the session usable.
			for _, code := range []int{http.StatusTooManyRequests, http.StatusBadGateway} {
				status.Store(int64(code))
				func() {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					wire, decoder := f.request(t, []byte(`{"method":"POST","path":"/v1/responses","headers":{}}`), nil)
					firstEnd := channel.RequestPrefixBytes + int(binary.BigEndian.Uint32(wire[channel.RequestPrefixBytes:]))
					input, output := io.Pipe()
					defer input.Close()
					defer output.Close()
					written := make(chan error, 1)
					go func() {
						_, err := output.Write(wire[:firstEnd])
						written <- err
					}()
					request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint.URL+sessionPath, input)
					if err != nil {
						t.Fatal(err)
					}
					request.Header.Set("Content-Type", sessionContentType)
					request.Header.Set(sessionNodeHeader, f.server.sessionNodeID)
					response, err := f.endpoint.Client().Do(request)
					if err != nil {
						t.Fatal("error response waited for unfinished upload", err)
					}
					metadata, _ := readSessionResponse(t, response, decoder)
					if metadata.Status != code {
						t.Fatalf("status=%d, want %d", metadata.Status, code)
					}
					if err := <-written; err != nil {
						t.Fatal(err)
					}
				}()
			}
		})
	}
}

func TestSessionHTTPCompletedUploadRejectedBeforeReadDoesNotCancelNextRequest(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%v", http2), func(t *testing.T) {
			f := newSessionHTTPFixture(t, func(ctx *requestContext) {
				if ctx.request.Header.Get("Authorization") == "" {
					ctx.writer.WriteHeader(http.StatusUnauthorized)
					return
				}
				if ctx.request.Context().Err() != nil {
					ctx.writer.WriteHeader(499)
					return
				}
				if _, err := io.Copy(io.Discard, ctx.request.Body); err != nil {
					t.Error(err)
				}
				ctx.writer.WriteHeader(http.StatusNoContent)
			}, http2)
			for _, credential := range []string{"", "Bearer accepted", "Bearer accepted"} {
				metadata, err := json.Marshal(sessionRequestMetadata{Method: http.MethodPost, Path: "/v1/responses", Headers: map[string]string{"Authorization": credential}})
				if err != nil {
					t.Fatal(err)
				}
				wire, decoder := f.request(t, metadata, []byte(`{}`))
				response := f.post(t, wire, true)
				inner, _ := readSessionResponse(t, response, decoder)
				want := http.StatusNoContent
				if credential == "" {
					want = http.StatusUnauthorized
				}
				if inner.Status != want {
					t.Fatalf("inner status = %d, want %d", inner.Status, want)
				}
			}
		})
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
	for _, invalid := range []struct {
		recordSize int
		mutate     func([]byte) []byte
	}{
		{channel.MaxRecordPlaintext, func(wire []byte) []byte { return wire[:len(wire)-1] }},
		{channel.MaxRecordPlaintext, func(wire []byte) []byte { wire[len(wire)-1] ^= 1; return wire }},
		{channel.MaxRecordPlaintext, func(wire []byte) []byte { return append(wire, 0) }},
		// Only the final upload record may be short.
		{1, func(wire []byte) []byte { return wire }},
	} {
		wire, decoder := f.requestWithRecordSize(t, metadata, []byte("body"), invalid.recordSize)
		result, _ := readSessionResponse(t, f.post(t, invalid.mutate(wire), true), decoder)
		if result.Status != 400 {
			t.Fatal("accepted invalid body")
		}
	}
	if dispatched.Load() != 0 {
		t.Fatal("invalid input reached dispatch")
	}
	f.server.requests.start()
	wire, decoder := f.request(t, metadata, []byte("undispatched request body"))
	result, unavailable := readSessionResponse(t, f.post(t, wire, true), decoder)
	if result.Status != 503 || !result.Closing || !bytes.Contains(unavailable, []byte("gateway_draining")) || dispatched.Load() != 0 {
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
		if got := server.memory.reserved.Load(); got != encryptedSessionRetainedBytes+minimumRequestWeightBytes {
			t.Errorf("duplicated initial reservation: %d", got)
		}
		ctx.memory.release()
		if got := server.memory.reserved.Load(); got != encryptedSessionRetainedBytes+int64(sessionAdapterRetainedBytes) {
			t.Errorf("released live encryption buffers: %d", got)
		}
		ctx.writer.WriteHeader(204)
	}, true)
	server = f.server
	wire, decoder := f.request(t, []byte(`{"method":"POST","path":"/v1/responses","headers":{}}`), nil)
	metadata, _ := readSessionResponse(t, f.post(t, wire, true), decoder)
	if metadata.Status != 204 || f.server.memory.reserved.Load() != encryptedSessionRetainedBytes {
		t.Fatal("transport did not release after its final write")
	}
}

func sessionTestHello(t *testing.T) ([]byte, []byte) {
	t.Helper()
	encoded, err := os.ReadFile("../stogas/confidential/channel/testdata/setup.json")
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
		bifrostCtx, state, cancel, err := newRequestContext(ctx, time.Now(), resolution, apiCredential{Raw: "secret"}, stogas.DefaultAdapter{}, "")
		if err != nil {
			t.Error(err)
			ctx.writer.WriteHeader(500)
			return
		}
		defer cancel()
		if !wantsMetadata(bifrostCtx) || !state.SingleUseRequestID || state.RequestID == "client-chosen" {
			t.Error("request identity or metadata selection lost")
		}
		state.FinalEvent = &billing.RequestEvent{CreatedAt: "2026-08-24T12:34:56.789Z", Usage: billing.RequestUsage{BilledCostUSD: "0", UpstreamCostUSD: "0", Meters: billing.EventMeters{}}}
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
	if !verifyReceipt(publicKey, result.Receipt, boot, sha256.Sum256(body), sha256.Sum256([]byte(`{"error":"limited"}`))) {
		t.Fatal("binary E2EE receipt does not cover original content")
	}
}
