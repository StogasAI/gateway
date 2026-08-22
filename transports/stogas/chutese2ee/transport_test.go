package chutese2ee

import (
	"bytes"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

func TestTransportEncryptsAndTargetsVerifiedInstance(t *testing.T) {
	instanceKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	var invokeCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != invocationPath {
			response.WriteHeader(http.StatusTooManyRequests)
			return
		}
		invokeCalls.Add(1)
		if request.URL.Path != invocationPath || request.Method != http.MethodPost {
			t.Errorf("invoke request = %s %s", request.Method, request.URL.Path)
		}
		wantHeaders := map[string]string{
			"Authorization":            "Bearer managed-key",
			"Content-Type":             "application/octet-stream",
			"X-Chute-Id":               testChuteID,
			"X-Instance-Id":            testInstanceID,
			"X-E2E-Nonce":              strings.Repeat("T", 32),
			"X-E2E-Stream":             "false",
			"X-E2E-Path":               "/v1/chat/completions",
			"X-E2EE-Usage-Passthrough": "false",
		}
		for name, want := range wantHeaders {
			if got := request.Header.Get(name); got != want {
				t.Errorf("header %s = %q, want %q", name, got, want)
			}
		}
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Errorf("read encrypted request: %v", readErr)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		if bytes.Contains(body, []byte("private prompt")) {
			t.Error("outer request contains plaintext prompt")
		}
		object, decryptErr := decryptRequestObjectForTest(instanceKey, body)
		if decryptErr != nil {
			t.Errorf("decrypt request: %v", decryptErr)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		var responsePublicKey string
		if decodeErr := json.Unmarshal(object["e2e_response_pk"], &responsePublicKey); decodeErr != nil {
			t.Errorf("decode response public key: %v", decodeErr)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", "application/octet-stream")
		_, _ = response.Write(encryptUnaryResponseForTest(t, responsePublicKey, []byte(`{"id":"private-response","choices":[]}`)))
	}))
	defer server.Close()

	transport := transportWithPoolForTest(
		t,
		server.URL,
		instanceKey,
		strings.Repeat("T", 32),
		strings.Repeat("U", 32),
		strings.Repeat("V", 32),
		strings.Repeat("W", 32),
		strings.Repeat("X", 32),
	)
	defer transport.Close()
	// Keep the test limited to the single-use invocation. Background ticket
	// replenishment has its own retry tests and can use the same test origin.
	transport.pools.mu.Lock()
	transport.pools.warming[testChuteID] = true
	transport.pools.mu.Unlock()
	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)
	request.Header.SetMethod(http.MethodPost)
	request.Header.SetContentType("application/json")
	request.Header.Set("Authorization", "Bearer managed-key")
	request.SetRequestURI("http://provider.invalid/v1/chat/completions")
	request.SetBodyString(`{"model":"upstream-model","messages":[{"role":"user","content":"private prompt"}]}`)

	retry, err := transport.RoundTrip(nil, request, response)
	if err != nil || retry {
		t.Fatalf("RoundTrip retry=%t error=%v", retry, err)
	}
	if response.StatusCode() != http.StatusOK {
		t.Fatalf("response status = %d, body=%s", response.StatusCode(), response.Body())
	}
	if got := string(response.Body()); got != `{"id":"private-response","choices":[]}` {
		t.Fatalf("decrypted response = %s", got)
	}
	if invokeCalls.Load() != 1 {
		t.Fatalf("invoke calls = %d", invokeCalls.Load())
	}
	if snapshot := transport.Diagnostics(); len(snapshot.Chutes) != 1 || snapshot.Chutes[0].UsableTickets != 4 {
		t.Fatalf("unexpected diagnostics: %#v", snapshot)
	}
}

func TestTransportUsesCredentialScopedBYOKPool(t *testing.T) {
	instanceKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	var invokeCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != invocationPath {
			response.WriteHeader(http.StatusTooManyRequests)
			return
		}
		invokeCalls.Add(1)
		if got := request.Header.Get("Authorization"); got != "Bearer user-key" {
			t.Errorf("authorization = %q, want customer key", got)
		}
		if got := request.Header.Get("X-E2E-Nonce"); got != strings.Repeat("B", 32) {
			t.Errorf("ticket = %q, want customer-scoped ticket", got)
		}
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Errorf("read encrypted request: %v", readErr)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		object, decryptErr := decryptRequestObjectForTest(instanceKey, body)
		if decryptErr != nil {
			t.Errorf("decrypt request: %v", decryptErr)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		var responsePublicKey string
		if decodeErr := json.Unmarshal(object["e2e_response_pk"], &responsePublicKey); decodeErr != nil {
			t.Errorf("decode response public key: %v", decodeErr)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", "application/octet-stream")
		_, _ = response.Write(encryptUnaryResponseForTest(t, responsePublicKey, []byte(`{"id":"byok-response","choices":[]}`)))
	}))
	defer server.Close()

	transport := transportWithPoolForTest(t, server.URL, instanceKey, strings.Repeat("M", 32))
	defer transport.Close()
	credential, release, err := transport.acquireCredential("user-key")
	if err != nil {
		t.Fatal(err)
	}
	installPoolForTest(credential.pools, instanceKey, strings.Repeat("B", 32))
	release()

	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)
	request.Header.SetMethod(http.MethodPost)
	request.Header.Set("Authorization", "Bearer user-key")
	request.SetRequestURI("http://provider.invalid/v1/chat/completions")
	request.SetBodyString(`{"model":"upstream-model","messages":[{"role":"user","content":"private prompt"}]}`)

	if retry, roundTripErr := transport.RoundTrip(nil, request, response); roundTripErr != nil || retry {
		t.Fatalf("RoundTrip retry=%t error=%v", retry, roundTripErr)
	}
	if response.StatusCode() != http.StatusOK || string(response.Body()) != `{"id":"byok-response","choices":[]}` {
		t.Fatalf("response status=%d body=%s", response.StatusCode(), response.Body())
	}
	if invokeCalls.Load() != 1 {
		t.Fatalf("invoke calls = %d", invokeCalls.Load())
	}
	if _, ok := transport.pools.take(testModelTarget, time.Now()); !ok {
		t.Fatal("customer invocation consumed the managed ticket pool")
	}
	snapshot := transport.Diagnostics()
	if snapshot.CredentialPools != 2 || snapshot.BYOKCredentialPools != 1 ||
		len(snapshot.Chutes) != 1 || snapshot.Chutes[0].CredentialPools != 2 ||
		snapshot.Chutes[0].VerifiedInstances != 1 {
		t.Fatalf("customer pool health was not safely aggregated: %#v", snapshot)
	}
}

func TestTransportNeverRetriesInvokeAndAppliesCooldown(t *testing.T) {
	instanceKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == invocationPath {
			calls.Add(1)
		}
		response.Header().Set("Retry-After", "30")
		response.WriteHeader(http.StatusTooManyRequests)
		_, _ = response.Write([]byte(`{"detail":"busy"}`))
	}))
	defer server.Close()

	transport := transportWithPoolForTest(
		t,
		server.URL,
		instanceKey,
		strings.Repeat("A", 32),
		strings.Repeat("B", 32),
		strings.Repeat("C", 32),
		strings.Repeat("D", 32),
		strings.Repeat("E", 32),
	)
	defer transport.Close()
	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)
	request.Header.SetMethod(http.MethodPost)
	request.Header.Set("Authorization", "Bearer managed-key")
	request.SetRequestURI("http://provider.invalid/v1/chat/completions")
	request.SetBodyString(`{"model":"upstream-model","messages":[]}`)

	if retry, err := transport.RoundTrip(nil, request, response); err != nil || retry {
		t.Fatalf("RoundTrip retry=%t error=%v", retry, err)
	}
	if response.StatusCode() != http.StatusTooManyRequests || calls.Load() != 1 {
		t.Fatalf("status=%d calls=%d", response.StatusCode(), calls.Load())
	}
	if _, ok := transport.pools.take(testModelTarget, time.Now()); ok {
		t.Fatal("expected rate-limited instance to remain in cooldown")
	}
	transport.pools.mu.Lock()
	remaining := len(transport.pools.pools[testChuteID].Instances[testInstanceID].Values)
	transport.pools.mu.Unlock()
	if remaining != 4 {
		t.Fatalf("remaining tickets = %d, want 4", remaining)
	}
}

func TestTransportRetriesPreComputeInstanceFailureWithFreshTicket(t *testing.T) {
	firstKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	const secondInstanceID = "33333333-3333-4333-8333-333333333333"
	var calls atomic.Int32
	var nonces []string
	var instanceIDs []string
	var ciphertexts [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != invocationPath {
			response.WriteHeader(http.StatusTooManyRequests)
			return
		}
		call := calls.Add(1)
		nonces = append(nonces, request.Header.Get("X-E2E-Nonce"))
		instanceIDs = append(instanceIDs, request.Header.Get("X-Instance-Id"))
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Errorf("read request: %v", readErr)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		ciphertexts = append(ciphertexts, append([]byte(nil), body...))
		if call == 1 {
			response.WriteHeader(http.StatusTooManyRequests)
			_, _ = response.Write([]byte(`{"detail":"Instance is at maximum capacity, try again later"}`))
			return
		}
		if request.Header.Get("X-Instance-Id") != secondInstanceID {
			t.Errorf("fallback instance = %q", request.Header.Get("X-Instance-Id"))
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		object, decryptErr := decryptRequestObjectForTest(secondKey, body)
		if decryptErr != nil {
			t.Errorf("decrypt fallback request: %v", decryptErr)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		var responsePublicKey string
		if decodeErr := json.Unmarshal(object["e2e_response_pk"], &responsePublicKey); decodeErr != nil {
			t.Errorf("decode fallback response key: %v", decodeErr)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = response.Write(encryptUnaryResponseForTest(t, responsePublicKey, []byte(`{"id":"fallback","choices":[]}`)))
	}))
	defer server.Close()

	transport, err := New(Options{
		APIKey:     "managed-key",
		APIBaseURL: server.URL,
		ResolveModel: func(model string) (ModelTarget, bool) {
			return testModelTarget, model == "upstream-model"
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	now := time.Now()
	firstPublicKey := base64.StdEncoding.EncodeToString(firstKey.EncapsulationKey().Bytes())
	secondPublicKey := base64.StdEncoding.EncodeToString(secondKey.EncapsulationKey().Bytes())
	transport.pools.install(testModelTarget, []discoveredInstance{
		{ID: testInstanceID, PublicKey: firstPublicKey, Tickets: []string{strings.Repeat("A", 32)}},
		{ID: secondInstanceID, PublicKey: secondPublicKey, Tickets: []string{strings.Repeat("B", 32)}},
	}, now.Add(time.Minute))
	transport.pools.mu.Lock()
	transport.pools.verified[testChuteID] = map[string]verifiedInstance{
		testInstanceID:   {InstanceID: testInstanceID, PublicKey: firstPublicKey, GPUCount: testGPUCount, ValidUntil: now.Add(time.Minute)},
		secondInstanceID: {InstanceID: secondInstanceID, PublicKey: secondPublicKey, GPUCount: testGPUCount, ValidUntil: now.Add(time.Minute)},
	}
	transport.pools.warming[testChuteID] = true
	transport.pools.mu.Unlock()

	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)
	request.Header.SetMethod(http.MethodPost)
	request.Header.Set("Authorization", "Bearer managed-key")
	request.SetRequestURI("http://provider.invalid/v1/chat/completions")
	request.SetBodyString(`{"model":"upstream-model","messages":[{"role":"user","content":"private prompt"}]}`)
	if retry, roundTripErr := transport.RoundTrip(nil, request, response); roundTripErr != nil || retry {
		t.Fatalf("RoundTrip retry=%t error=%v", retry, roundTripErr)
	}
	if response.StatusCode() != http.StatusOK || string(response.Body()) != `{"id":"fallback","choices":[]}` {
		t.Fatalf("fallback response status=%d body=%s", response.StatusCode(), response.Body())
	}
	if calls.Load() != 2 || len(nonces) != 2 || nonces[0] == nonces[1] ||
		len(instanceIDs) != 2 || instanceIDs[0] == instanceIDs[1] ||
		len(ciphertexts) != 2 || bytes.Equal(ciphertexts[0], ciphertexts[1]) {
		t.Fatalf("calls=%d nonces=%v instances=%v ciphertexts=%d", calls.Load(), nonces, instanceIDs, len(ciphertexts))
	}
}

func TestTransportTriesEveryDiscoveredInstanceBeforeReturningCapacity(t *testing.T) {
	instanceKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	instanceIDs := make(map[string]struct{})
	nonces := make(map[string]struct{})
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != invocationPath {
			response.WriteHeader(http.StatusTooManyRequests)
			return
		}
		calls.Add(1)
		instanceIDs[request.Header.Get("X-Instance-Id")] = struct{}{}
		nonces[request.Header.Get("X-E2E-Nonce")] = struct{}{}
		response.WriteHeader(http.StatusTooManyRequests)
		_, _ = response.Write([]byte(`{"detail":"Instance is at maximum capacity, try again later"}`))
	}))
	defer server.Close()

	transport, err := New(Options{
		APIKey:     "managed-key",
		APIBaseURL: server.URL,
		ResolveModel: func(model string) (ModelTarget, bool) {
			return testModelTarget, model == "upstream-model"
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	now := time.Now()
	publicKey := base64.StdEncoding.EncodeToString(instanceKey.EncapsulationKey().Bytes())
	discovered := make([]discoveredInstance, 0, maximumDiscoveredInstances)
	verified := make(map[string]verifiedInstance, maximumDiscoveredInstances)
	for index := 1; index <= maximumDiscoveredInstances; index++ {
		instanceID := fmt.Sprintf("10000000-0000-4000-8000-%012d", index)
		ticket := strings.Repeat(string(rune('A'+index-1)), 32)
		discovered = append(discovered, discoveredInstance{
			ID: instanceID, PublicKey: publicKey, Tickets: []string{ticket},
		})
		verified[instanceID] = verifiedInstance{
			InstanceID: instanceID, PublicKey: publicKey, GPUCount: testGPUCount, ValidUntil: now.Add(time.Minute),
		}
	}
	transport.pools.install(testModelTarget, discovered, now.Add(time.Minute))
	transport.pools.mu.Lock()
	transport.pools.verified[testChuteID] = verified
	transport.pools.warming[testChuteID] = true
	transport.pools.mu.Unlock()

	request := fasthttp.AcquireRequest()
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)
	request.Header.SetMethod(http.MethodPost)
	request.Header.Set("Authorization", "Bearer managed-key")
	request.SetRequestURI("http://provider.invalid/v1/chat/completions")
	request.SetBodyString(`{"model":"upstream-model","messages":[]}`)
	if retry, roundTripErr := transport.RoundTrip(nil, request, response); roundTripErr != nil || retry {
		t.Fatalf("RoundTrip retry=%t error=%v", retry, roundTripErr)
	}
	if response.StatusCode() != http.StatusTooManyRequests ||
		calls.Load() != maximumDiscoveredInstances ||
		len(instanceIDs) != maximumDiscoveredInstances ||
		len(nonces) != maximumDiscoveredInstances {
		t.Fatalf(
			"status=%d calls=%d instances=%d nonces=%d",
			response.StatusCode(), calls.Load(), len(instanceIDs), len(nonces),
		)
	}
}

func TestInvokeFallbackRequiresExactPreComputeFailure(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{name: "consumed nonce", status: http.StatusForbidden, body: `{"detail":"Invalid, expired, or already-used nonce"}`, want: true},
		{name: "missing instance", status: http.StatusNotFound, body: `{"detail":"Instance not found"}`, want: true},
		{name: "inactive instance", status: http.StatusGone, body: `{"detail":"Instance is no longer active"}`, want: true},
		{name: "instance needs key exchange", status: http.StatusBadGateway, body: `{"detail":"Instance requires key exchange, try a different instance"}`, want: true},
		{name: "relayed forbidden", status: http.StatusForbidden, body: `{"detail":"Instance returned status 403"}`},
		{name: "hidden inaccessible chute", status: http.StatusNotFound, body: `{"detail":"Chute not found"}`},
		{name: "lookalike inactive detail", status: http.StatusGone, body: `{"detail":"instance is no longer active"}`},
		{name: "capacity before compute", status: http.StatusTooManyRequests, body: `{"detail":"Instance is at maximum capacity, try again later"}`, want: true},
		{name: "generic rate limit", status: http.StatusTooManyRequests, body: `{"detail":"Rate limit exceeded. Try again later."}`},
		{name: "ambiguous unavailable", status: http.StatusBadGateway, body: `{"detail":"Instance returned status 502"}`},
		{name: "malformed", status: http.StatusForbidden, body: `{`},
		{name: "empty", status: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(response)
			response.SetStatusCode(test.status)
			response.SetBodyString(test.body)
			if got := safeInvokeFallbackResponse(response); got != test.want {
				t.Fatalf("safe fallback = %t, want %t", got, test.want)
			}
		})
	}
}

func TestTicketReservationErrorClassification(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		managed    bool
		wantStatus int
		wantCode   string
	}{
		{
			name:       "BYOK authentication",
			err:        errors.Join(ErrNoUsableTicket, &httpStatusError{StatusCode: http.StatusUnauthorized}),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "upstream_authentication_failed",
		},
		{
			name:       "BYOK access",
			err:        errors.Join(ErrNoUsableTicket, &httpStatusError{StatusCode: http.StatusForbidden}),
			wantStatus: http.StatusForbidden,
			wantCode:   "upstream_access_denied",
		},
		{
			name:       "managed authentication is an operator failure",
			err:        errors.Join(ErrNoUsableTicket, &httpStatusError{StatusCode: http.StatusUnauthorized}),
			managed:    true,
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "upstream_configuration_error",
		},
		{
			name: "rate limit retains bounded retry advice",
			err: errors.Join(ErrNoUsableTicket, &ticketRefillBackoffError{
				Cause:      &httpStatusError{StatusCode: http.StatusTooManyRequests},
				RetryAfter: 7 * time.Second,
			}),
			wantStatus: http.StatusTooManyRequests,
			wantCode:   "upstream_rate_limit_error",
		},
		{
			name:       "attestation failure is unavailable",
			err:        errors.Join(ErrNoUsableTicket, ErrAttestationFailed),
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "upstream_verification_failed",
		},
		{
			name:       "empty verified capacity is unavailable",
			err:        ErrNoUsableTicket,
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "upstream_capacity_unavailable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(response)
			setTicketReservationError(response, test.err, test.managed)
			if response.StatusCode() != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.StatusCode(), test.wantStatus)
			}
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body(), &body); err != nil || body.Error.Code != test.wantCode {
				t.Fatalf("body = %s error=%v", response.Body(), err)
			}
			if test.wantStatus == http.StatusTooManyRequests && string(response.Header.Peek("Retry-After")) != "7" {
				t.Fatalf("Retry-After = %q", response.Header.Peek("Retry-After"))
			}
		})
	}
}

func TestTransportRejectsUnsupportedWireRequestsBeforeDispatch(t *testing.T) {
	instanceKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		response.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	transport := transportWithPoolForTest(t, server.URL, instanceKey, strings.Repeat("T", 32))
	defer transport.Close()

	tests := []struct {
		name          string
		method        string
		path          string
		authorization string
		body          string
		wantStatus    int
	}{
		{name: "wrong route", method: http.MethodPost, path: "/v1/responses", authorization: "Bearer managed-key", body: `{"model":"upstream-model"}`, wantStatus: http.StatusBadGateway},
		{name: "wrong method", method: http.MethodGet, path: "/v1/chat/completions", authorization: "Bearer managed-key", body: `{"model":"upstream-model"}`, wantStatus: http.StatusBadGateway},
		{name: "unknown model", method: http.MethodPost, path: "/v1/chat/completions", authorization: "Bearer managed-key", body: `{"model":"unknown"}`, wantStatus: http.StatusServiceUnavailable},
		{name: "invalid JSON", method: http.MethodPost, path: "/v1/chat/completions", authorization: "Bearer managed-key", body: `{`, wantStatus: http.StatusBadGateway},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := fasthttp.AcquireRequest()
			response := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseRequest(request)
			defer fasthttp.ReleaseResponse(response)
			request.Header.SetMethod(test.method)
			request.Header.Set("Authorization", test.authorization)
			request.SetRequestURI("http://provider.invalid" + test.path)
			request.SetBodyString(test.body)
			if _, err := transport.RoundTrip(nil, request, response); err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			if response.StatusCode() != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.StatusCode(), test.wantStatus)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream calls = %d", calls.Load())
	}
}

func TestCredentialPoolsAreReusedIsolatedAndRetired(t *testing.T) {
	transport, err := New(Options{
		APIKey:     "managed-key",
		APIBaseURL: "http://provider.invalid",
		ResolveModel: func(string) (ModelTarget, bool) {
			return testModelTarget, true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	first, releaseFirst, err := transport.acquireCredential("customer-a")
	if err != nil {
		t.Fatal(err)
	}
	again, releaseAgain, err := transport.acquireCredential("customer-a")
	if err != nil {
		t.Fatal(err)
	}
	second, releaseSecond, err := transport.acquireCredential("customer-b")
	if err != nil {
		t.Fatal(err)
	}
	managed, releaseManaged, err := transport.acquireCredential("managed-key")
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatal("the same customer key did not reuse its credential state")
	}
	if first == second || first.pools == second.pools {
		t.Fatal("different customer keys shared credential state")
	}
	if first.diagnostics != second.diagnostics || first.diagnostics != transport.diagnostics {
		t.Fatal("node diagnostics were not safely aggregated")
	}
	if managed != transport.managedCredential || managed.pools != transport.pools {
		t.Fatal("managed key did not reuse managed fleet state")
	}
	releaseFirst()
	releaseAgain()
	releaseSecond()
	releaseManaged()

	transport.credentialsMu.Lock()
	first.lastUsed = time.Now().Add(-credentialIdleLifetime)
	transport.credentialsMu.Unlock()
	third, releaseThird, err := transport.acquireCredential("customer-c")
	if err != nil {
		t.Fatal(err)
	}
	releaseThird()
	if third == first {
		t.Fatal("different key reused retired state")
	}
	if first.api.apiKey != "" {
		t.Fatal("retired credential secret was not cleared")
	}
	transport.credentialsMu.Lock()
	_, retained := transport.credentials[fingerprintCredential("customer-a")]
	transport.credentialsMu.Unlock()
	if retained {
		t.Fatal("idle customer credential was retained")
	}
}

func TestOwnedInvokeStreamRetainsCredentialUntilClosed(t *testing.T) {
	var releases atomic.Int32
	upstream := fasthttp.AcquireResponse()
	upstream.SetBodyStream(io.NopCloser(strings.NewReader("stream")), -1)
	stream := &ownedInvokeStream{
		source:   upstream.BodyStream(),
		response: upstream,
		onClose:  func() { releases.Add(1) },
	}

	if releases.Load() != 0 {
		t.Fatal("stream released its credential before close")
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close stream twice: %v", err)
	}
	if releases.Load() != 1 {
		t.Fatalf("credential release count = %d, want 1", releases.Load())
	}
}

func TestAuthorizationIsStrictlyParsed(t *testing.T) {
	invalidAuthorizations := []string{
		"",
		"Basic abc",
		"Bearer ",
		"Bearer  key",
		"Bearer key with-space",
		"Bearer key\twith-tab",
		"Bearer kéy",
		"Bearer " + strings.Repeat("a", maximumChutesAPIKeyLength+1),
	}
	for _, authorization := range invalidAuthorizations {
		if _, parseErr := chutesAPIKeyFromAuthorization(authorization); parseErr == nil {
			t.Fatalf("accepted invalid authorization of length %d", len(authorization))
		}
	}
	if apiKey, parseErr := chutesAPIKeyFromAuthorization("bearer valid-key_123"); parseErr != nil || apiKey != "valid-key_123" {
		t.Fatalf("valid authorization rejected: key=%q err=%v", apiKey, parseErr)
	}
}

func TestInvokeClientKeepsRequestWriteTimeoutForStreams(t *testing.T) {
	client := newInvokeClient(false, true)
	if client.WriteTimeout != 5*time.Minute {
		t.Fatalf("stream write timeout = %s, want 5m", client.WriteTimeout)
	}
	if client.ReadTimeout != 0 {
		t.Fatalf("stream read timeout = %s, want unlimited", client.ReadTimeout)
	}
	if client.MaxConnDuration != 0 {
		t.Fatalf("stream maximum connection duration = %s, want unlimited", client.MaxConnDuration)
	}
}

func TestProductionOriginPolicyDoesNotDependOnPostQuantumTLS(t *testing.T) {
	for _, requirePostQuantumTLS := range []bool{false, true} {
		if client, err := newAPIClient("managed-key", "https://example.com", true, requirePostQuantumTLS); err == nil {
			client.close()
			t.Fatalf("non-production origin accepted with post-quantum TLS=%t", requirePostQuantumTLS)
		}
	}
	client, err := newAPIClient("managed-key", productionAPIBaseURL, true, false)
	if err != nil {
		t.Fatalf("production origin rejected: %v", err)
	}
	client.close()
}

func transportWithPoolForTest(t *testing.T, baseURL string, instanceKey *mlkem.DecapsulationKey768, tickets ...string) *Transport {
	t.Helper()
	transport, err := New(Options{
		APIKey:     "managed-key",
		APIBaseURL: baseURL,
		ResolveModel: func(model string) (ModelTarget, bool) {
			return testModelTarget, model == "upstream-model"
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	installPoolForTest(transport.pools, instanceKey, tickets...)
	return transport
}

func installPoolForTest(pool *poolState, instanceKey *mlkem.DecapsulationKey768, tickets ...string) {
	now := time.Now()
	publicKey := base64.StdEncoding.EncodeToString(instanceKey.EncapsulationKey().Bytes())
	pool.install(
		testModelTarget,
		[]discoveredInstance{{ID: testInstanceID, PublicKey: publicKey, Tickets: tickets}},
		now.Add(time.Minute),
	)
	pool.mu.Lock()
	pool.verified[testChuteID] = map[string]verifiedInstance{
		testInstanceID: {
			InstanceID: testInstanceID,
			PublicKey:  publicKey,
			GPUCount:   testGPUCount,
			VerifiedAt: now,
			ValidUntil: now.Add(time.Minute),
		},
	}
	pool.mu.Unlock()
}
