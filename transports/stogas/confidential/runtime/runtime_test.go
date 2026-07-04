package runtime

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/confidential/identity"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
)

func TestStartDisabledIsNoop(t *testing.T) {
	runtime, err := Start(context.Background(), stogas.ConfidentialConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if runtime != nil {
		t.Fatalf("disabled confidential runtime should be nil, got %#v", runtime)
	}
}

func TestStartLocalMockBuildsQuoteManagerAndProofService(t *testing.T) {
	config := testConfig("mock")
	runtime, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if runtime.Identity == nil || runtime.Quotes == nil || runtime.Proofs == nil {
		t.Fatalf("runtime did not initialize confidential components: %#v", runtime)
	}
	if !runtime.EntropyReady {
		t.Fatal("runtime did not mark entropy ready after startup probe")
	}
	snapshot, err := runtime.Quotes.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Payload.ReleaseMeasurement != config.ReleaseMeasurement ||
		snapshot.Payload.ActiveCertSHA256 != config.ActiveCertSHA256 ||
		snapshot.Payload.TLSSPKISHA256 != runtime.Identity.TLSSPKISHA256 ||
		snapshot.Payload.HPKEPublicKey != runtime.Identity.HPKEPublicKey ||
		snapshot.Payload.Ed25519PublicKey != runtime.Identity.Ed25519PublicKey {
		t.Fatalf("quote payload did not bind runtime identity/config: %#v", snapshot.Payload)
	}
	if len(snapshot.Quote) == 0 {
		t.Fatal("expected initial mock quote")
	}
	output, err := runtime.Proofs.Build(context.Background(), proofhttp.Input{
		CatalogHash:          snapshot.Payload.CatalogHash,
		CatalogNodeIDs:       []string{"node-a"},
		ProcessedRequestJSON: []byte(`{"request":true}`),
		ResponseJSON:         []byte(`{"response":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if output.Headers[proofhttp.HeaderQuote] != base64.RawURLEncoding.EncodeToString(snapshot.Quote) {
		t.Fatalf("proof header did not use current quote: %#v", output.Headers)
	}
	if !proof.Verify(runtime.Identity.Ed25519PublicKeyRaw, output.Object.ProcessedHash, output.Object.ProcessedSignature) {
		t.Fatal("proof signature was not produced by runtime identity")
	}
}

func TestStartFailsClosedWhenEntropyIsUnavailable(t *testing.T) {
	old := waitForEntropy
	waitForEntropy = func(ctx context.Context, timeout time.Duration) error {
		return errors.New("entropy unavailable")
	}
	defer func() {
		waitForEntropy = old
	}()

	_, err := Start(context.Background(), testConfig("mock"))
	if err == nil || !strings.Contains(err.Error(), "confidential entropy readiness failed") {
		t.Fatalf("expected entropy startup failure, got %v", err)
	}
}

func TestStartSEVSNPFailsClosedWithoutHardwareQuoteDevice(t *testing.T) {
	_, err := Start(context.Background(), testConfig("sev-snp"))
	if err == nil || !strings.Contains(err.Error(), "initial confidential quote refresh failed") {
		t.Fatalf("expected sev-snp startup to fail closed without hardware quote device, got %v", err)
	}
}

func TestStartSendsInitialHeartbeatAndBackgroundReadiness(t *testing.T) {
	heartbeatCh := make(chan map[string]any, 1)
	readinessCh := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "Bearer control-token" {
			t.Fatalf("unexpected authorization header: %q", r.Header.Get("authorization"))
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		switch r.URL.Path {
		case "/api/gateway-nodes/heartbeat":
			heartbeatCh <- body
			writeHeartbeatResponse(t, w, strings.Repeat("9", 64), "")
		case "/api/gateway-nodes/readiness":
			readinessCh <- body
			_, _ = w.Write([]byte(`{"generation_id":"` + strings.Repeat("9", 64) + `","ok":true}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	config := testConfig("mock")
	config.CertExpiresAt = time.Now().UTC().Add(90 * 24 * time.Hour)
	config.ChipID = strings.Repeat("1", 128)
	config.ControlAllowHTTP = true
	config.ControlToken = "control-token"
	config.ControlURL = server.URL
	config.EndpointAddress = "10.0.0.10"
	config.EndpointPort = 8443
	config.HeartbeatInterval = time.Hour
	config.ReadinessInterval = time.Hour

	runtime, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	select {
	case body := <-heartbeatCh:
		if body["chip_id"] != config.ChipID || body["region"] != config.Region {
			t.Fatalf("unexpected heartbeat body: %#v", body)
		}
		if _, ok := body["quote"].(string); !ok {
			t.Fatalf("heartbeat did not include full quote: %#v", body)
		}
	case <-time.After(time.Second):
		t.Fatal("initial heartbeat was not sent")
	}

	select {
	case body := <-readinessCh:
		if body["generation_id"] != strings.Repeat("9", 64) ||
			body["address"] != "10.0.0.10" ||
			body["local_ready"] != false {
			t.Fatalf("unexpected readiness body: %#v", body)
		}
		reason, _ := body["reason"].(string)
		if strings.Contains(reason, "latest bundle") || !strings.Contains(reason, "secrets are not ready") {
			t.Fatalf("readiness did not use heartbeat bundle admission: %#v", body)
		}
	case <-time.After(time.Second):
		t.Fatal("readiness observation was not sent")
	}

	if runtime.Control.GenerationID() != strings.Repeat("9", 64) {
		t.Fatalf("generation id not recorded: %q", runtime.Control.GenerationID())
	}

	runtime.Control.entropyReady = false
	result := runtime.Control.readinessResult()
	if !hasReason(result.Reasons, "entropy is not ready") {
		t.Fatalf("readiness did not include entropy failure: %#v", result)
	}
}

func TestControlLoopSubmitsCertificateCSRInstruction(t *testing.T) {
	generationID := strings.Repeat("9", 64)
	csrCh := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "Bearer control-token" {
			t.Fatalf("unexpected authorization header: %q", r.Header.Get("authorization"))
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		switch r.URL.Path {
		case "/api/gateway-nodes/heartbeat":
			writeHeartbeatResponse(t, w, generationID, `{"action":"request_csr","order_id":"order-1","dns_names":["Gateway.Stogas.AI","gateway.stogas.ai"],"common_name":"gateway.stogas.ai"}`)
		case "/api/gateway-nodes/cert/csr":
			csrCh <- body
			_, _ = w.Write([]byte(`{"generation_id":"` + generationID + `","ok":true,"order_id":"order-1"}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	config := testConfig("mock")
	config.CertExpiresAt = time.Now().UTC().Add(90 * 24 * time.Hour)
	config.ChipID = strings.Repeat("1", 128)
	config.ControlAllowHTTP = true
	config.ControlToken = "control-token"
	config.ControlURL = server.URL
	config.HeartbeatInterval = time.Hour

	runtime, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	select {
	case body := <-csrCh:
		if body["generation_id"] != generationID ||
			body["order_id"] != "order-1" ||
			body["tls_spki_sha256"] != runtime.Identity.TLSSPKISHA256 {
			t.Fatalf("unexpected CSR submission body: %#v", body)
		}
		if body["common_name"] != "gateway.stogas.ai" {
			t.Fatalf("unexpected CSR common name: %#v", body)
		}
		dnsNames, ok := body["dns_names"].([]any)
		if !ok || len(dnsNames) != 1 || dnsNames[0] != "gateway.stogas.ai" {
			t.Fatalf("CSR DNS names were not normalized: %#v", body["dns_names"])
		}
		csrEncoded, _ := body["csr_der"].(string)
		csrDER, err := base64.RawURLEncoding.DecodeString(csrEncoded)
		if err != nil {
			t.Fatalf("CSR was not base64url: %v", err)
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			t.Fatal(err)
		}
		if err := csr.CheckSignature(); err != nil {
			t.Fatalf("CSR signature did not verify: %v", err)
		}
		spki, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if identity.SHA256Hex(spki) != runtime.Identity.TLSSPKISHA256 {
			t.Fatal("CSR did not use the runtime TLS key")
		}
	case <-time.After(time.Second):
		t.Fatal("certificate CSR was not submitted")
	}
}

func TestControlLoopInstallCertificateInstructionRefreshesQuoteAndReheartbeats(t *testing.T) {
	generationID := strings.Repeat("9", 64)
	var mu sync.Mutex
	var instruction string
	var heartbeatBodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "Bearer control-token" {
			t.Fatalf("unexpected authorization header: %q", r.Header.Get("authorization"))
		}
		if r.URL.Path != "/api/gateway-nodes/heartbeat" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		heartbeatBodies = append(heartbeatBodies, body)
		nextInstruction := instruction
		instruction = ""
		mu.Unlock()
		writeHeartbeatResponse(t, w, generationID, nextInstruction)
	}))
	defer server.Close()

	config := testConfig("mock")
	config.CertExpiresAt = time.Now().UTC().Add(30 * 24 * time.Hour)
	config.ChipID = strings.Repeat("1", 128)
	config.ControlAllowHTTP = true
	config.ControlToken = "control-token"
	config.ControlURL = server.URL
	config.HeartbeatInterval = time.Hour

	runtime, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	newExpiry := time.Now().UTC().Truncate(time.Second).Add(90 * 24 * time.Hour)
	chainPEM, leafDER := selfSignedRuntimeLeaf(t, runtime.Identity, 20, newExpiry)
	newHash := identity.CertSHA256Hex(leafDER)
	instructionJSON, err := json.Marshal(map[string]string{
		"action":          "install_renewed_chain",
		"order_id":        "order-2",
		"cert_chain_pem":  string(chainPEM),
		"new_cert_sha256": newHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	instruction = string(instructionJSON)
	before := len(heartbeatBodies)
	mu.Unlock()

	if err := runtime.Control.sendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	after := len(heartbeatBodies)
	last := heartbeatBodies[len(heartbeatBodies)-1]
	mu.Unlock()
	if after-before != 2 {
		t.Fatalf("expected instruction heartbeat plus refreshed follow-up heartbeat, got %d", after-before)
	}
	reportData, ok := last["report_data"].(map[string]any)
	if !ok {
		t.Fatalf("follow-up heartbeat missing report_data: %#v", last)
	}
	if reportData["active_cert_sha256"] != config.ActiveCertSHA256 {
		t.Fatalf("install instruction should not activate the new certificate: %#v", reportData)
	}
	accepted, ok := reportData["accepted_cert_sha256"].([]any)
	if !ok || !jsonArrayContains(accepted, newHash) {
		t.Fatalf("follow-up heartbeat did not bind the staged certificate hash: %#v", reportData)
	}
	if runtime.Control.LastCertificateError() != nil {
		t.Fatalf("unexpected certificate instruction error: %v", runtime.Control.LastCertificateError())
	}

	activateJSON, err := json.Marshal(map[string]string{
		"action":      "activate_staged",
		"order_id":    "order-2",
		"cert_sha256": newHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	instruction = string(activateJSON)
	before = len(heartbeatBodies)
	mu.Unlock()

	if err := runtime.Control.sendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	after = len(heartbeatBodies)
	last = heartbeatBodies[len(heartbeatBodies)-1]
	mu.Unlock()
	if after-before != 2 {
		t.Fatalf("expected activate heartbeat plus refreshed follow-up heartbeat, got %d", after-before)
	}
	reportData, ok = last["report_data"].(map[string]any)
	if !ok {
		t.Fatalf("follow-up heartbeat missing report_data after activation: %#v", last)
	}
	if reportData["active_cert_sha256"] != newHash {
		t.Fatalf("activate instruction did not switch active certificate: %#v", reportData)
	}
	accepted, ok = reportData["accepted_cert_sha256"].([]any)
	if !ok || !jsonArrayContains(accepted, config.ActiveCertSHA256) || !jsonArrayContains(accepted, newHash) {
		t.Fatalf("activation should preserve old and new accepted hashes: %#v", reportData)
	}

	pruneJSON, err := json.Marshal(map[string]string{
		"action":             "prune_accepted",
		"order_id":           "order-2",
		"active_cert_sha256": newHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	instruction = string(pruneJSON)
	before = len(heartbeatBodies)
	mu.Unlock()

	if err := runtime.Control.sendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	after = len(heartbeatBodies)
	last = heartbeatBodies[len(heartbeatBodies)-1]
	mu.Unlock()
	if after-before != 2 {
		t.Fatalf("expected prune heartbeat plus refreshed follow-up heartbeat, got %d", after-before)
	}
	reportData, ok = last["report_data"].(map[string]any)
	if !ok {
		t.Fatalf("follow-up heartbeat missing report_data after prune: %#v", last)
	}
	accepted, ok = reportData["accepted_cert_sha256"].([]any)
	if !ok || len(accepted) != 1 || accepted[0] != newHash {
		t.Fatalf("prune instruction did not drop old certificate hash: %#v", reportData)
	}
	if runtime.Control.LastCertificateError() != nil {
		t.Fatalf("unexpected certificate instruction error after prune: %v", runtime.Control.LastCertificateError())
	}
}

func TestStartFailsClosedWhenInitialHeartbeatIsRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Rejected confidential gateway heartbeat","reason":"unknown chip_id"}`))
	}))
	defer server.Close()

	config := testConfig("mock")
	config.CertExpiresAt = time.Now().UTC().Add(90 * 24 * time.Hour)
	config.ChipID = strings.Repeat("1", 128)
	config.ControlAllowHTTP = true
	config.ControlToken = "control-token"
	config.ControlURL = server.URL
	config.HeartbeatInterval = time.Hour

	_, err := Start(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "initial confidential heartbeat failed") {
		t.Fatalf("expected initial heartbeat failure, got %v", err)
	}
}

func TestDeriveNodeIDUsesBootIdentityNotCertificateHash(t *testing.T) {
	config := testConfig("mock")
	config.ChipID = strings.Repeat("1", 128)
	material := &identity.Material{
		TLSSPKISHA256:     strings.Repeat("2", 64),
		HPKEPublicKey:     "aHBrZQ",
		Ed25519PublicKey:  "ZWRrZXk",
	}
	catalogHash := strings.Repeat("3", 64)

	first := deriveNodeID(config, material, catalogHash)
	config.ActiveCertSHA256 = strings.Repeat("4", 64)
	config.AcceptedCertSHA256 = []string{strings.Repeat("4", 64)}
	if renewed := deriveNodeID(config, material, catalogHash); renewed != first {
		t.Fatalf("certificate renewal changed node id: %s != %s", renewed, first)
	}

	changedIdentity := *material
	changedIdentity.HPKEPublicKey = "aHBrZTI"
	if next := deriveNodeID(config, &changedIdentity, catalogHash); next == first {
		t.Fatal("identity key change should create a different node id")
	}
	if next := deriveNodeID(config, material, strings.Repeat("5", 64)); next == first {
		t.Fatal("catalog change should create a different node id")
	}
}

func TestRuntimeCertificateRenewalRefreshesReportDataImmediately(t *testing.T) {
	config := testConfig("mock")
	config.CertExpiresAt = time.Now().UTC().Add(30 * 24 * time.Hour)
	runtime, err := Start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	newExpiry := time.Now().UTC().Truncate(time.Second).Add(90 * 24 * time.Hour)
	chainPEM, leafDER := selfSignedRuntimeLeaf(t, runtime.Identity, 10, newExpiry)
	newHash := identity.CertSHA256Hex(leafDER)
	staged, err := runtime.StageRenewedCertificate(context.Background(), chainPEM)
	if err != nil {
		t.Fatal(err)
	}
	if staged.ActiveCertSHA256 != config.ActiveCertSHA256 || !hasReason(staged.AcceptedCertSHA256, newHash) {
		t.Fatalf("renewed certificate was not staged as dual-hash state: %#v", staged)
	}
	snapshot, err := runtime.Quotes.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Payload.ActiveCertSHA256 != config.ActiveCertSHA256 || !hasReason(snapshot.Payload.AcceptedCertSHA256, newHash) {
		t.Fatalf("quote did not refresh with staged certificate hashes: %#v", snapshot.Payload)
	}

	active, err := runtime.ActivateStagedCertificate(context.Background(), newHash)
	if err != nil {
		t.Fatal(err)
	}
	if active.ActiveCertSHA256 != newHash || !active.ExpiresAt.Equal(newExpiry) {
		t.Fatalf("certificate was not activated: %#v", active)
	}
	snapshot, err = runtime.Quotes.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Payload.ActiveCertSHA256 != newHash || !hasReason(snapshot.Payload.AcceptedCertSHA256, config.ActiveCertSHA256) {
		t.Fatalf("quote did not refresh after activation: %#v", snapshot.Payload)
	}

	pruned, err := runtime.PruneAcceptedCertificates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned.AcceptedCertSHA256) != 1 || pruned.AcceptedCertSHA256[0] != newHash {
		t.Fatalf("accepted certificate hashes were not pruned: %#v", pruned)
	}
	snapshot, err = runtime.Quotes.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Payload.AcceptedCertSHA256) != 1 || snapshot.Payload.AcceptedCertSHA256[0] != newHash {
		t.Fatalf("quote did not refresh after certificate prune: %#v", snapshot.Payload)
	}
}

func testConfig(mode string) stogas.ConfidentialConfig {
	return stogas.ConfidentialConfig{
		AcceptedCertSHA256: []string{strings.Repeat("c", 64)},
		ActiveCertSHA256:   strings.Repeat("c", 64),
		AttesterMode:       mode,
		Enabled:            true,
		EntropyTimeout:     time.Second,
		QuoteRefresh:       time.Hour,
		Region:             "global",
		ReleaseMeasurement: strings.Repeat("a", 64),
	}
}

func hasReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

func selfSignedRuntimeLeaf(t *testing.T, material *identity.Material, serial int64, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "gateway.stogas.ai"},
		DNSNames:              []string{"gateway.stogas.ai"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &material.TLSPrivateKey.PublicKey, material.TLSPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), der
}

func writeHeartbeatResponse(t *testing.T, w http.ResponseWriter, generationID string, certificateInstructionJSON string) {
	t.Helper()
	if certificateInstructionJSON == "" {
		certificateInstructionJSON = "null"
	}
	_, _ = w.Write([]byte(`{"bundle":{"active_cert_accepted":true,"latest_bundle_verified":true,"node_in_latest_bundle":true,"sequence":3},"certificate_instruction":` + certificateInstructionJSON + `,"generation_id":"` + generationID + `","node_id":"` + strings.Repeat("8", 64) + `","ok":true,"quote_verified_at":"2026-07-01T12:00:00Z"}`))
}

func jsonArrayContains(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
