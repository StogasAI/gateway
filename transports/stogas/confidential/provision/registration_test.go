package provision

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	verifier "github.com/StogasAI/verifier/go"
	"github.com/StogasAI/verifier/go/reference"
	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
)

func TestControlDeliveryRefusesRedirectsAndMalformedCompletions(t *testing.T) {
	request, node := registrationFixture(t)
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

const testNode = "amber-anchor-01"

// testBoot returns fresh node keys, the boot document they commit and its
// signing key, read back from the document as Control would.
func testBoot(t *testing.T) (*verifier.NodeKeys, []byte, []byte) {
	t.Helper()
	keys, err := verifier.GenerateNodeKeys(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Close)
	data, err := keys.ReportData(1, [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	report := make([]byte, 0x4a0)
	copy(report[0x50:], data[:])
	document, err := keys.BootDocument(1, [32]byte{1}, [32]byte{2}, report, [32]byte{3}, [32]byte{4})
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
	return keys, document, public
}

func registrationFixture(t *testing.T) (BootRegistration, string) {
	t.Helper()
	_, document, _ := testBoot(t)
	return NewBootRegistration("7700d119-e111-4c67-bfeb-17e127c38100", document, []byte("test CSR; server performs possession verification")), testNode
}

func TestRegistrationChallengeAndExactBootRetry(t *testing.T) {
	request, node := registrationFixture(t)
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
		got, err := io.ReadAll(r.Body)
		if want, _ := json.Marshal(request); err != nil || !bytes.Equal(got, want) {
			t.Error("boot retry changed request bytes")
		}
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(RegistrationResponse{Status: "pending", NodeID: node})
			return
		}
		json.NewEncoder(w).Encode(RegistrationResponse{Status: "ready", NodeID: node, Inclusion: json.RawMessage(`{"test":"verified separately"}`), Provisioning: json.RawMessage(`{"sealed":"opened by the node keys"}`)})
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

// verifyBootRequest independently checks a request signature with Go's ML-DSA-65 and Ed25519.
func verifyBootRequest(public []byte, domain, node string, issued int64, encoded string) bool {
	signature, err := base64.RawURLEncoding.DecodeString(encoded)
	message := binary.BigEndian.AppendUint64(append([]byte(domain+node), 0), uint64(issued))
	return err == nil && reference.VerifySignature(public, message, signature) == nil
}

func TestCertificateRenewalCompletion(t *testing.T) {
	keys, document, public := testBoot(t)
	node := testNode
	boot := attest.BootEvidence{Document: document, Inclusion: []byte(`{"fixture":"inclusion"}`)}
	for _, tc := range []struct {
		name     string
		response BootCertificateResponse
		valid    bool
	}{
		{"pending", BootCertificateResponse{Status: "pending", NodeID: node}, true},
		{"ready", BootCertificateResponse{Status: "ready", NodeID: node, CertificatePEM: "public certificate; validated by installer"}, true},
		{"wrong owner", BootCertificateResponse{Status: "ready", NodeID: "amber-anchor-02", CertificatePEM: "certificate"}, false},
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
				if request.NodeID != node || time.Since(time.UnixMilli(request.Issued)).Abs() > time.Minute ||
					!verifyBootRequest(public, "stogas.certificate-renewal.v1\x00", node, request.Issued, request.Signature) {
					t.Error("renewal was not signed by this node")
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tc.response)
			}))
			defer server.Close()
			client := Client{BaseURL: server.URL, AllowInsecureLocal: true}
			_, err := client.RenewBootCertificate(context.Background(), node, boot, []byte{1}, keys)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
	if _, err := (Client{}).RenewBootCertificate(context.Background(), "", attest.BootEvidence{}, []byte{1}, keys); err == nil {
		t.Fatal("accepted absent node identity")
	}
	if _, err := (Client{}).RenewBootCertificate(context.Background(), node, attest.BootEvidence{}, []byte{1}, nil); err == nil {
		t.Fatal("renewed without node key")
	}
}

func TestRegistrationRejectsInconsistentCompletionAndUntrustedNames(t *testing.T) {
	request, node := registrationFixture(t)
	sealed := json.RawMessage(`{"sealed":true}`)
	for name, response := range map[string]RegistrationResponse{
		"different node":   {Status: "pending", NodeID: node + "a"},
		"unknown status":   {Status: "approved", NodeID: node},
		"pending proof":    {Status: "pending", NodeID: node, Inclusion: json.RawMessage(`{}`)},
		"pending secrets":  {Status: "pending", NodeID: node, Provisioning: sealed},
		"ready no proof":   {Status: "ready", NodeID: node, Provisioning: sealed},
		"ready null proof": {Status: "ready", NodeID: node, Inclusion: json.RawMessage(`null`), Provisioning: sealed},
		"ready no secrets": {Status: "ready", NodeID: node, Inclusion: json.RawMessage(`{}`)},
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
	request, node := registrationFixture(t)
	client := Client{BaseURL: "https://unreachable.invalid"}
	for _, change := range []func(*BootRegistration){
		func(v *BootRegistration) { v.InstanceID = "not-an-instance" },
		func(v *BootRegistration) { v.CSRDER += "=" },
		func(v *BootRegistration) { v.CSRDER = strings.Repeat("A", 21847) },
		func(v *BootRegistration) { v.Boot = json.RawMessage(`{`) },
	} {
		altered := request
		change(&altered)
		if _, err := client.RegisterBoot(context.Background(), altered, node); err == nil {
			t.Fatal("accepted invalid local boot")
		}
	}
}

func TestRegistrationCancellationAndTypedFailure(t *testing.T) {
	request, node := registrationFixture(t)
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

func TestRegistrationAcknowledgementBindsPurposeAndExactBoot(t *testing.T) {
	keys, document, public := testBoot(t)
	node := testNode
	boot := attest.BootEvidence{Document: document, Inclusion: []byte(`{"fixture":"inclusion"}`)}
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
				if !verifyBootRequest(public, "stogas.registration-complete.v1\x00", node, request.IssuedAtMS, request.Signature) {
					t.Error("invalid completion signature")
				}
				responseNode := node
				if status == "wrong-node" {
					responseNode = "amber-anchor-99"
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"status": status, "node_id": responseNode})
			}))
			defer server.Close()
			err := (Client{BaseURL: server.URL, AllowInsecureLocal: true}).CompleteBootRegistration(t.Context(), node, boot, keys)
			if (err == nil) != (status == "complete") {
				t.Fatalf("completion result: %v", err)
			}
		})
	}
}
