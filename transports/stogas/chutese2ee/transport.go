package chutese2ee

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
)

type Options struct {
	APIKey                  string
	APIBaseURL              string
	ResolveModel            ModelResolver
	RequireProductionOrigin bool
	RequirePostQuantumTLS   bool
}

type Transport struct {
	api                *apiClient
	resolveModel       ModelResolver
	unaryClient        *fasthttp.Client
	streamClient       *fasthttp.Client
	diagnostics        *diagnostics
	attestor           *attestor
	pools              *poolState
	managedCredential  *credentialState
	managedFingerprint credentialFingerprint
	credentialsMu      sync.Mutex
	credentials        map[credentialFingerprint]*credentialState
	credentialWG       sync.WaitGroup
	closed             atomic.Bool
}

func New(options Options) (*Transport, error) {
	if options.ResolveModel == nil {
		return nil, errors.New("Chutes catalog model resolver is required")
	}
	api, err := newAPIClient(
		options.APIKey,
		options.APIBaseURL,
		options.RequireProductionOrigin,
		options.RequirePostQuantumTLS,
	)
	if err != nil {
		return nil, err
	}
	diagnostics := &diagnostics{}
	attestor, err := newAttestor(api, diagnostics)
	if err != nil {
		api.close()
		return nil, err
	}
	transport := &Transport{
		api:          api,
		resolveModel: options.ResolveModel,
		diagnostics:  diagnostics,
		attestor:     attestor,
	}
	transport.pools = newPoolState(api, attestor, diagnostics)
	transport.managedCredential = &credentialState{
		api:         api,
		pools:       transport.pools,
		diagnostics: diagnostics,
		lastUsed:    time.Now(),
	}
	transport.managedFingerprint = fingerprintCredential(api.apiKey)
	transport.credentials = make(map[credentialFingerprint]*credentialState)
	transport.unaryClient = newInvokeClient(options.RequirePostQuantumTLS, false)
	transport.streamClient = newInvokeClient(options.RequirePostQuantumTLS, true)
	return transport, nil
}

func newInvokeClient(requirePostQuantumTLS, streaming bool) *fasthttp.Client {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if requirePostQuantumTLS {
		tlsConfig.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	}
	client := &fasthttp.Client{
		TLSConfig:                 tlsConfig,
		MaxConnsPerHost:           5000,
		MaxIdleConnDuration:       30 * time.Second,
		MaxConnDuration:           5 * time.Minute,
		MaxConnWaitTimeout:        30 * time.Second,
		ReadTimeout:               5 * time.Minute,
		WriteTimeout:              30 * time.Second,
		MaxResponseBodySize:       maxDecryptedResponse + (2 << 20),
		MaxIdemponentCallAttempts: 1,
		NoDefaultUserAgentHeader:  true,
		StreamResponseBody:        streaming,
		ConnPoolStrategy:          fasthttp.FIFO,
		RetryIfErr: func(_ *fasthttp.Request, _ int, _ error) (bool, bool) {
			return false, false
		},
	}
	if streaming {
		client.ReadTimeout = 0
		client.MaxConnDuration = 0
	}
	return client
}

func (t *Transport) Close() {
	if t == nil || !t.closed.CompareAndSwap(false, true) {
		return
	}
	t.credentialsMu.Lock()
	dynamicCredentials := make([]*credentialState, 0, len(t.credentials))
	for _, credential := range t.credentials {
		dynamicCredentials = append(dynamicCredentials, credential)
	}
	t.credentials = nil
	t.credentialsMu.Unlock()
	t.credentialWG.Wait()
	closeCredentialStates(dynamicCredentials)
	if t.pools != nil {
		t.pools.close()
	}
	if t.attestor != nil {
		t.attestor.close()
	}
	if t.api != nil {
		t.api.close()
	}
	if t.unaryClient != nil {
		t.unaryClient.CloseIdleConnections()
	}
	if t.streamClient != nil {
		t.streamClient.CloseIdleConnections()
	}
}

func (t *Transport) Diagnostics() DiagnosticsSnapshot {
	if t == nil || t.pools == nil || t.diagnostics == nil {
		return DiagnosticsSnapshot{GeneratedAt: time.Now().UTC(), Chutes: []ChuteDiagnostic{}}
	}
	t.credentialsMu.Lock()
	poolStates := make([]*poolState, 0, len(t.credentials)+1)
	poolStates = append(poolStates, t.pools)
	activeCredentialPools := 0
	if t.managedCredential != nil && t.managedCredential.active > 0 {
		activeCredentialPools++
	}
	for _, credential := range t.credentials {
		poolStates = append(poolStates, credential.pools)
		if credential.active > 0 {
			activeCredentialPools++
		}
	}
	credentialPools := len(poolStates)
	byokCredentialPools := len(t.credentials)
	t.credentialsMu.Unlock()

	snapshot := t.diagnostics.snapshot(aggregatePoolHealth(poolStates))
	snapshot.CredentialPools = credentialPools
	snapshot.ActiveCredentialPools = activeCredentialPools
	snapshot.BYOKCredentialPools = byokCredentialPools
	return snapshot
}

func (t *Transport) RoundTrip(_ *fasthttp.HostClient, request *fasthttp.Request, response *fasthttp.Response) (bool, error) {
	if t == nil || t.closed.Load() {
		setSyntheticError(response, http.StatusServiceUnavailable, "upstream_unavailable", "Chutes private inference is unavailable", 0)
		return false, nil
	}
	originalPath := string(request.URI().Path())
	if originalPath != "/v1/chat/completions" || string(request.Header.Method()) != http.MethodPost {
		setSyntheticError(response, http.StatusBadGateway, "upstream_protocol_error", "Unsupported Chutes private inference request", 0)
		return false, nil
	}
	payload := append([]byte(nil), request.Body()...)
	defer clear(payload)
	var metadata struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if err := json.Unmarshal(payload, &metadata); err != nil || strings.TrimSpace(metadata.Model) == "" {
		setSyntheticError(response, http.StatusBadGateway, "upstream_protocol_error", "Invalid Chutes private inference request", 0)
		return false, nil
	}
	target, ok := t.resolveModel(metadata.Model)
	if !ok || !validModelTarget(target) {
		setSyntheticError(response, http.StatusServiceUnavailable, "upstream_unavailable", "Chutes private inference is unavailable", 0)
		return false, nil
	}
	chuteID := target.ChuteID
	apiKey, err := chutesAPIKeyFromAuthorization(string(request.Header.Peek("Authorization")))
	if err != nil {
		setSyntheticError(response, http.StatusServiceUnavailable, "upstream_unavailable", "Chutes private inference is unavailable", 0)
		return false, nil
	}
	credential, releaseCredential, err := t.acquireCredential(apiKey)
	if err != nil {
		setSyntheticError(response, http.StatusServiceUnavailable, "upstream_unavailable", "Chutes private inference is unavailable", 0)
		return false, nil
	}
	defer func() {
		if releaseCredential != nil {
			releaseCredential()
		}
	}()
	credential.diagnostics.registerModel(chuteID, metadata.Model)
	for attempt := 0; attempt < maximumInvokeAttempts; attempt++ {
		ticket, reserveErr := credential.pools.reserve(target)
		if reserveErr != nil {
			setTicketReservationError(response, reserveErr, credential == t.managedCredential)
			return false, nil
		}
		encrypted, encryptErr := encryptRequest(ticket.PublicKey, payload)
		if encryptErr != nil {
			credential.diagnostics.recordProtocolFailure(chuteID)
			setSyntheticError(response, http.StatusBadGateway, "upstream_protocol_error", "Chutes private inference encryption failed", 0)
			return false, nil
		}
		configureInvokeRequest(request, credential, ticket, encrypted.Body, metadata.Stream, originalPath)
		if metadata.Stream {
			streamOwnsCredential, streamErr := t.roundTripStream(
				credential,
				request,
				response,
				ticket,
				encrypted,
				releaseCredential,
			)
			clear(encrypted.Body)
			if streamOwnsCredential {
				releaseCredential = nil
			}
			if streamErr != nil || streamOwnsCredential || attempt+1 >= maximumInvokeAttempts ||
				!safeInvokeFallbackResponse(response) {
				return false, streamErr
			}
			response.Reset()
			continue
		}
		unaryErr := t.roundTripUnary(credential, request, response, ticket, encrypted)
		clear(encrypted.Body)
		if unaryErr != nil || attempt+1 >= maximumInvokeAttempts ||
			!safeInvokeFallbackResponse(response) {
			return false, unaryErr
		}
		response.Reset()
	}
	return false, nil
}

func setTicketReservationError(response *fasthttp.Response, err error, managed bool) {
	retryAfter := time.Second
	var backoff *ticketRefillBackoffError
	if errors.As(err, &backoff) && backoff.RetryAfter > retryAfter {
		retryAfter = min(backoff.RetryAfter, time.Minute)
	}
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) {
		if statusErr.RetryAfter > retryAfter {
			retryAfter = min(statusErr.RetryAfter, time.Minute)
		}
		switch statusErr.StatusCode {
		case http.StatusUnauthorized:
			if !managed {
				setSyntheticError(response, http.StatusUnauthorized, "invalid_api_key", "The Chutes API key is invalid", 0)
				return
			}
		case http.StatusForbidden:
			if !managed {
				setSyntheticError(response, http.StatusForbidden, "upstream_access_denied", "The Chutes API key cannot access this model", 0)
				return
			}
		case http.StatusTooManyRequests:
			setSyntheticError(response, http.StatusTooManyRequests, "upstream_rate_limit_error", "Chutes ticket discovery is rate limited", retryAfter)
			return
		}
	}
	setSyntheticError(response, http.StatusServiceUnavailable, "upstream_unavailable", "No verified Chutes private capacity is currently available", retryAfter)
}

func configureInvokeRequest(
	request *fasthttp.Request,
	credential *credentialState,
	ticket reservedTicket,
	body []byte,
	stream bool,
	originalPath string,
) {
	request.Header.Reset()
	request.SetRequestURI(credential.api.baseURL.String() + invocationPath)
	request.Header.SetMethod(http.MethodPost)
	request.Header.SetContentType("application/octet-stream")
	request.Header.Set("Authorization", "Bearer "+credential.api.apiKey)
	request.Header.Set("X-Chute-Id", ticket.ChuteID)
	request.Header.Set("X-Instance-Id", ticket.InstanceID)
	request.Header.Set("X-E2E-Nonce", ticket.Value)
	request.Header.Set("X-E2E-Stream", fmt.Sprintf("%t", stream))
	request.Header.Set("X-E2E-Path", originalPath)
	request.Header.Set("X-E2EE-Usage-Passthrough", "false")
	request.SetBodyRaw(body)
}

func safeInvokeFallbackResponse(response *fasthttp.Response) bool {
	if response == nil || len(response.Body()) == 0 || len(response.Body()) > 4096 {
		return false
	}
	var body struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(response.Body(), &body); err != nil {
		return false
	}
	switch response.StatusCode() {
	case http.StatusForbidden:
		return body.Detail == "Invalid, expired, or already-used nonce"
	case http.StatusNotFound:
		return body.Detail == "Instance not found"
	case http.StatusGone:
		return body.Detail == "Instance is no longer active"
	case http.StatusTooManyRequests:
		return body.Detail == "Instance is at maximum capacity, try again later"
	case http.StatusBadGateway:
		return body.Detail == "Instance requires key exchange, try a different instance"
	default:
		return false
	}
}

func (t *Transport) roundTripUnary(credential *credentialState, request *fasthttp.Request, response *fasthttp.Response, ticket reservedTicket, encrypted *encryptedRequest) error {
	err := t.unaryClient.Do(request, response)
	status := response.StatusCode()
	credential.pools.observeInvoke(ticket, status, parseRetryAfter(string(response.Header.Peek("Retry-After")), time.Now()), err)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return nil
	}
	plaintext, err := decryptResponse(encrypted.ResponseKey, response.Body())
	if err != nil {
		credential.diagnostics.recordProtocolFailure(ticket.ChuteID)
		setSyntheticError(response, http.StatusBadGateway, "upstream_protocol_error", "Invalid encrypted response from Chutes", 0)
		return nil
	}
	response.SetBodyRaw(plaintext)
	response.Header.SetContentType("application/json")
	response.Header.Del("Content-Encoding")
	response.Header.Del("Transfer-Encoding")
	return nil
}

func (t *Transport) roundTripStream(
	credential *credentialState,
	request *fasthttp.Request,
	response *fasthttp.Response,
	ticket reservedTicket,
	encrypted *encryptedRequest,
	releaseCredential func(),
) (bool, error) {
	upstream := fasthttp.AcquireResponse()
	if err := t.streamClient.Do(request, upstream); err != nil {
		fasthttp.ReleaseResponse(upstream)
		credential.pools.observeInvoke(ticket, 0, 0, err)
		return false, err
	}
	status := upstream.StatusCode()
	credential.pools.observeInvoke(ticket, status, parseRetryAfter(string(upstream.Header.Peek("Retry-After")), time.Now()), nil)
	if status != http.StatusOK {
		copyStreamErrorResponse(upstream, response)
		fasthttp.ReleaseResponse(upstream)
		return false, nil
	}
	upstream.Header.CopyTo(&response.Header)
	response.SetStatusCode(status)
	response.Header.SetContentType("text/event-stream")
	response.Header.Del("Content-Encoding")
	owned := &ownedInvokeStream{
		source:   upstream.BodyStream(),
		response: upstream,
		onClose:  releaseCredential,
	}
	decrypted := newStreamReader(owned, encrypted.ResponseKey, func() {
		credential.diagnostics.recordProtocolFailure(ticket.ChuteID)
	})
	response.SetBodyStream(decrypted, -1)
	return true, nil
}

type ownedInvokeStream struct {
	source   io.Reader
	response *fasthttp.Response
	onClose  func()
	once     sync.Once
}

func (s *ownedInvokeStream) Read(target []byte) (int, error) {
	if s == nil || s.source == nil {
		return 0, io.EOF
	}
	return s.source.Read(target)
}

func (s *ownedInvokeStream) Close() error {
	var closeErr error
	s.once.Do(func() {
		if closer, ok := s.source.(io.Closer); ok {
			closeErr = closer.Close()
		}
		fasthttp.ReleaseResponse(s.response)
		if s.onClose != nil {
			s.onClose()
		}
	})
	return closeErr
}

func copyStreamErrorResponse(source, target *fasthttp.Response) {
	source.Header.CopyTo(&target.Header)
	target.SetStatusCode(source.StatusCode())
	body, err := io.ReadAll(io.LimitReader(source.BodyStream(), (2<<20)+1))
	if err != nil || len(body) > 2<<20 {
		setSyntheticError(target, http.StatusBadGateway, "upstream_protocol_error", "Invalid error response from Chutes", 0)
		return
	}
	target.SetBodyRaw(body)
}

func setSyntheticError(response *fasthttp.Response, status int, errorType, message string, retryAfter time.Duration) {
	response.Reset()
	response.SetStatusCode(status)
	response.Header.SetContentType("application/json")
	if retryAfter > 0 {
		seconds := max(1, int(retryAfter.Round(time.Second)/time.Second))
		response.Header.Set("Retry-After", fmt.Sprintf("%d", seconds))
	}
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"type":    errorType,
			"message": message,
			"code":    errorType,
		},
	})
	response.SetBodyRaw(body)
}
