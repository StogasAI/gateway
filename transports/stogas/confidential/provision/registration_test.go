package provision

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
)

func TestControlDeliveryRefusesRedirectsAndMalformedCompletions(t *testing.T) {
	request, node, _ := registrationFixture(t)
	var forwarded atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, destination.URL, status)
			}))
			defer origin.Close()
			client := Client{BaseURL: origin.URL, AllowInsecureLocal: true, AccessClientID: "test-id", AccessClientSecret: "test-secret"}
			if _, err := client.RegisterBoot(t.Context(), request, node); err == nil {
				t.Fatal("followed Control redirect")
			}
		})
	}
	if forwarded.Load() != 0 {
		t.Fatal("redirect destination received a registration or credential")
	}
	for name, body := range map[string]string{
		"unknown field":  `{"status":"pending","node_id":"` + node + `","unrecognized":true}`,
		"trailing value": `{"status":"pending","node_id":"` + node + `"} {}`,
		"truncated":      `{"status":"pending"`,
		"oversized":      strings.Repeat(" ", DefaultMaxResponseBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer origin.Close()
			client := Client{BaseURL: origin.URL, AllowInsecureLocal: true}
			if _, err := client.RegisterBoot(t.Context(), request, node); err == nil {
				t.Fatal("accepted malformed or oversized completion")
			}
		})
	}
}

func registrationFixture(t *testing.T) (BootRegistration, string, string) {
	t.Helper()
	encoded, err := os.ReadFile("../attest/testdata/node-boot-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Record attest.BootRecord `json:"record"`
	}
	if err := json.Unmarshal(encoded, &vector); err != nil {
		t.Fatal(err)
	}
	request := NewBootRegistration("7700d119-e111-4c67-bfeb-17e127c38100", vector.Record, []byte("test CSR; server performs possession verification"))
	digest, err := request.Boot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return request, attest.SNPNodeID([32]byte{1}), hex.EncodeToString(digest[:])
}

func TestRegistrationChallengeAndExactBootRetry(t *testing.T) {
	request, node, digest := registrationFixture(t)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("CF-Access-Client-Id") != "public-test-id" || r.Header.Get("CF-Access-Client-Secret") != "public-test-secret" {
			t.Error("missing Access admission credential")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/fleet/registration/challenge" {
			json.NewEncoder(w).Encode(RegistrationChallenge{Challenge: strings.Repeat("1", 64), ExpiresAt: time.Now().Add(time.Minute)})
			return
		}
		if r.URL.Path != "/api/fleet/registration" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var got BootRegistration
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil || got != request {
			t.Error("boot retry changed request bytes")
		}
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(RegistrationResponse{Status: "pending", NodeID: node})
			return
		}
		json.NewEncoder(w).Encode(RegistrationResponse{Status: "ready", NodeID: node, Inclusion: json.RawMessage(`{"test":"verified separately"}`), Provisioning: &BootProvisioning{Schema: BootProvisioningSchema, BootSHA256: digest}})
	}))
	defer server.Close()
	client := Client{BaseURL: server.URL, AllowInsecureLocal: true, AccessClientID: "public-test-id", AccessClientSecret: "public-test-secret"}
	if _, err := client.RegistrationChallenge(context.Background(), request.InstanceID); err != nil {
		t.Fatal(err)
	}
	pending, err := client.RegisterBoot(context.Background(), request, node)
	if err != nil || pending.Status != "pending" {
		t.Fatalf("pending: %v, %v", pending, err)
	}
	ready, err := client.RegisterBoot(context.Background(), request, node)
	if err != nil || ready.Status != "ready" || calls != 2 {
		t.Fatalf("ready: %v, %v", ready, err)
	}
}

func TestCertificateRenewalCompletion(t *testing.T) {
	registration, node, _ := registrationFixture(t)
	document, err := registration.Boot.Document()
	if err != nil {
		t.Fatal(err)
	}
	boot := attest.BootEvidence{Document: document, Inclusion: []byte(`{"fixture":"inclusion"}`)}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		response BootCertificateResponse
		valid    bool
	}{
		{"pending", BootCertificateResponse{Status: "pending", NodeID: node}, true},
		{"ready", BootCertificateResponse{Status: "ready", NodeID: node, CertificatePEM: "public certificate; validated by installer"}, true},
		{"wrong owner", BootCertificateResponse{Status: "ready", NodeID: attest.SNPNodeID([32]byte{2}), CertificatePEM: "certificate"}, false},
		{"missing", BootCertificateResponse{Status: "ready", NodeID: node}, false},
		{"premature", BootCertificateResponse{Status: "pending", NodeID: node, CertificatePEM: "certificate"}, false},
		{"unknown", BootCertificateResponse{Status: "other", NodeID: node}, false},
		{"oversized", BootCertificateResponse{Status: "ready", NodeID: node, CertificatePEM: strings.Repeat("x", 32*1024+1)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/fleet/registration/certificate" {
					t.Error("wrong certificate endpoint")
				}
				var request struct {
					NodeID    string          `json:"node_id"`
					Issued    int64           `json:"issued_at_ms"`
					Signature string          `json:"signature"`
					Boot      json.RawMessage `json:"boot"`
					Inclusion json.RawMessage `json:"inclusion"`
					CSR       string          `json:"csr_der"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
				}
				if !bytes.Equal(bytes.TrimSpace(request.Boot), bytes.TrimSpace(document)) || !bytes.Equal(request.Inclusion, boot.Inclusion) || request.CSR != "AQ" {
					t.Error("renewal omitted or changed its boot, proof or CSR")
				}
				message := append([]byte("stogas.certificate-renewal.v1\x00"), []byte(request.NodeID)...)
				message = append(message, 0)
				message = binary.BigEndian.AppendUint64(message, uint64(request.Issued))
				signature, err := base64.RawURLEncoding.DecodeString(request.Signature)
				if err != nil || request.NodeID != node || time.Since(time.UnixMilli(request.Issued)).Abs() > time.Minute || mldsa.Verify(key.PublicKey(), message, signature, nil) != nil {
					t.Error("renewal was not signed by this node")
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tc.response)
			}))
			defer server.Close()
			client := Client{BaseURL: server.URL, AllowInsecureLocal: true}
			_, err := client.RenewBootCertificate(context.Background(), node, boot, []byte{1}, key)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
	for _, invalid := range []string{"", "node", "wrong-name-" + strings.Repeat("0", 64), strings.ToUpper(node)} {
		if _, err := (Client{}).RenewBootCertificate(context.Background(), invalid, attest.BootEvidence{}, []byte{1}, key); err == nil {
			t.Fatal("accepted invalid node identity")
		}
	}
}

func TestRegistrationRejectsInconsistentCompletionAndUntrustedNames(t *testing.T) {
	request, node, digest := registrationFixture(t)
	for name, response := range map[string]RegistrationResponse{
		"different node":   {Status: "pending", NodeID: node + "a"},
		"unknown status":   {Status: "approved", NodeID: node},
		"pending proof":    {Status: "pending", NodeID: node, Inclusion: json.RawMessage(`{}`)},
		"pending secrets":  {Status: "pending", NodeID: node, Provisioning: &BootProvisioning{}},
		"ready no proof":   {Status: "ready", NodeID: node, Provisioning: &BootProvisioning{Schema: BootProvisioningSchema, BootSHA256: digest}},
		"ready no secrets": {Status: "ready", NodeID: node, Inclusion: json.RawMessage(`{}`)},
		"wrong boot":       {Status: "ready", NodeID: node, Inclusion: json.RawMessage(`{}`), Provisioning: &BootProvisioning{Schema: BootProvisioningSchema, BootSHA256: strings.Repeat("0", 64)}},
		"wrong profile":    {Status: "ready", NodeID: node, Inclusion: json.RawMessage(`{}`), Provisioning: &BootProvisioning{Schema: "other", BootSHA256: digest}},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(response) }))
			defer server.Close()
			client := Client{BaseURL: server.URL, AllowInsecureLocal: true}
			if _, err := client.RegisterBoot(context.Background(), request, node); err == nil {
				t.Fatal("accepted inconsistent completion")
			}
		})
	}
}

func TestRegistrationRejectsInvalidLocalInputsBeforeSending(t *testing.T) {
	request, node, _ := registrationFixture(t)
	client := Client{BaseURL: "https://unreachable.invalid"}
	for _, change := range []func(*BootRegistration){
		func(v *BootRegistration) { v.InstanceID = "not-an-instance" },
		func(v *BootRegistration) { v.CSRDER += "=" },
		func(v *BootRegistration) { v.CSRDER = strings.Repeat("A", 21847) },
		func(v *BootRegistration) { v.Boot.ReportData.RegistrationChallenge = strings.Repeat("0", 64) },
	} {
		altered := request
		change(&altered)
		if _, err := client.RegisterBoot(context.Background(), altered, node); err == nil {
			t.Fatal("accepted invalid local boot")
		}
	}
}

func TestRegistrationCancellationAndTypedFailure(t *testing.T) {
	request, node, _ := registrationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { cancel(); <-release }))
	defer func() { close(release); server.Close() }()
	client := Client{BaseURL: server.URL, AllowInsecureLocal: true}
	if _, err := client.RegisterBoot(ctx, request, node); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	failure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		w.Write([]byte(`{"error":"challenge_expired"}`))
	}))
	defer failure.Close()
	client.BaseURL = failure.URL
	_, err := client.RegisterBoot(context.Background(), request, node)
	var responseError *HTTPResponseError
	if !errors.As(err, &responseError) || responseError.Code != "challenge_expired" {
		t.Fatalf("typed failure: %v", err)
	}
}

func TestRegistrationChallengeRejectsExpiredAndNoncanonicalValues(t *testing.T) {
	for name, response := range map[string]RegistrationChallenge{
		"expired":        {Challenge: strings.Repeat("1", 64), ExpiresAt: time.Now().Add(-time.Second)},
		"missing expiry": {Challenge: strings.Repeat("1", 64)},
		"uppercase":      {Challenge: strings.Repeat("A", 64), ExpiresAt: time.Now().Add(time.Minute)},
		"short":          {Challenge: "11", ExpiresAt: time.Now().Add(time.Minute)},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(response) }))
			defer server.Close()
			client := Client{BaseURL: server.URL, AllowInsecureLocal: true}
			if _, err := client.RegistrationChallenge(context.Background(), "7700d119-e111-4c67-bfeb-17e127c38100"); err == nil {
				t.Fatal("accepted invalid challenge")
			}
		})
	}
}

func TestCertificateRenewalIndependentSignatureVector(t *testing.T) {
	data, err := os.ReadFile("../attest/testdata/node-boot-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Renewal struct {
			NodeID    string `json:"node_id"`
			Issued    int64  `json:"issued_at_ms"`
			Signature string `json:"signature"`
		} `json:"certificate_renewal"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := key.SignDeterministic(bootRequestTranscript(certificateRequestDomain, fixture.Renewal.NodeID, fixture.Renewal.Issued), &mldsa.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if base64.RawURLEncoding.EncodeToString(signed) != fixture.Renewal.Signature {
		t.Fatal("certificate renewal signature differs from independent vector")
	}
	if _, err := (Client{}).RenewBootCertificate(t.Context(), fixture.Renewal.NodeID, attest.BootEvidence{}, []byte{1}, nil); err == nil {
		t.Fatal("renewed without node key")
	}
}

func TestRegistrationAcknowledgementBindsPurposeAndExactBoot(t *testing.T) {
	registration, node, _ := registrationFixture(t)
	document, err := registration.Boot.Document()
	if err != nil {
		t.Fatal(err)
	}
	boot := attest.BootEvidence{Document: document, Inclusion: []byte(`{"fixture":"inclusion"}`)}
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"complete", "pending", "wrong-node"} {
		t.Run(status, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/fleet/registration/complete" {
					t.Error("wrong completion endpoint")
				}
				var request bootRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					return
				}
				if request.NodeID != node || !bytes.Equal(bytes.TrimSpace(request.Boot), bytes.TrimSpace(document)) || !bytes.Equal(request.Inclusion, boot.Inclusion) {
					t.Error("completion changed boot evidence")
				}
				signature, err := base64.RawURLEncoding.DecodeString(request.Signature)
				message := append([]byte("stogas.registration-complete.v1\x00"), []byte(node)...)
				message = binary.BigEndian.AppendUint64(append(message, 0), uint64(request.IssuedAtMS))
				if err != nil || mldsa.Verify(key.PublicKey(), message, signature, nil) != nil {
					t.Error("invalid completion signature")
				}
				responseNode := node
				if status == "wrong-node" {
					responseNode = attest.SNPNodeID([32]byte{99})
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"status": status, "node_id": responseNode})
			}))
			defer server.Close()
			err := (Client{BaseURL: server.URL, AllowInsecureLocal: true}).CompleteBootRegistration(t.Context(), node, boot, key)
			if (err == nil) != (status == "complete") {
				t.Fatalf("completion result: %v", err)
			}
		})
	}
}
