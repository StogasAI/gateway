package provision

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/confidential/quote"
	"github.com/maximhq/bifrost/transports/stogas/confidential/reportdata"
)

func TestSendHeartbeatPostsStrictControlContract(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	snapshot := testSnapshot(t, now)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/fleet/heartbeat" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("CF-Access-Client-Id") != "access-client-id" || r.Header.Get("CF-Access-Client-Secret") != "access-client-secret" {
			t.Fatalf("missing Cloudflare Access headers: %#v", r.Header)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["node_id"] != "node-1" {
			t.Fatalf("unexpected heartbeat identity: %#v", body)
		}
		if _, ok := body["chip_id"]; ok {
			t.Fatalf("heartbeat must not send host-derived chip_id: %#v", body)
		}
		if _, ok := body["region"]; ok {
			t.Fatalf("heartbeat must not send launch region: %#v", body)
		}
		if body["quote"] != base64.RawURLEncoding.EncodeToString([]byte("quote-bytes")) {
			t.Fatalf("quote was not base64url encoded: %#v", body["quote"])
		}
		if _, ok := body["quote_verifier"]; ok {
			t.Fatalf("heartbeat must not send legacy verifier metadata: %#v", body)
		}
		if _, ok := body["quote_verifier_jwt"]; ok {
			t.Fatalf("heartbeat must not send legacy verifier JWTs: %#v", body)
		}
		reportData, ok := body["report_data"].(map[string]any)
		if !ok || reportData["schema"] != reportdata.SchemaV1 {
			t.Fatalf("report data not sent as structured JSON: %#v", body["report_data"])
		}
		health, ok := body["health"].(map[string]any)
		if !ok || health["ready"] != false || health["last_quote_error"] != "drand fetch failed" {
			t.Fatalf("unexpected health payload: %#v", body["health"])
		}
		versions, ok := health["secret_versions"].(map[string]any)
		if !ok || versions["OPENAI_API_KEY"] != "1" {
			t.Fatalf("unexpected secret versions: %#v", health["secret_versions"])
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"certificate_instruction":null,"generation_id":"` + strings.Repeat("b", 64) + `","ok":true,"ready":true,"ready_until":"2026-07-01T12:10:00Z","secrets":null}`))
	}))
	defer server.Close()

	client := Client{
		AccessClientID:     "access-client-id",
		AccessClientSecret: "access-client-secret",
		BaseURL:            server.URL,
		AllowInsecureLocal: true,
	}
	result, err := client.SendHeartbeat(context.Background(), HeartbeatInput{
		CertExpiresAt: now.Add(90 * 24 * time.Hour),
		Health:        NodeHealth{Ready: false, LastQuoteError: "drand fetch failed", SecretVersions: map[string]string{"OPENAI_API_KEY": "1"}},
		NodeID:        "node-1",
		ObservedAt:    now,
		Quote:         snapshot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.GenerationID != strings.Repeat("b", 64) || !result.Ready || result.ReadyUntil == nil || !result.ReadyUntil.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("unexpected heartbeat response: %#v", result)
	}
	if result.CertificateInstruction != nil {
		t.Fatalf("unexpected certificate instruction: %#v", result.CertificateInstruction)
	}
}

func TestSendHeartbeatParsesCertificateInstruction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"certificate_instruction":{"action":"request_csr","common_name":"Gateway.Stogas.AI","dns_names":["Gateway.Stogas.AI","API.Stogas.AI","api.stogas.ai"],"order_id":"order-1"},"generation_id":"` + strings.Repeat("b", 64) + `","ok":true,"ready":false,"ready_until":null,"secrets":null}`))
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, AllowInsecureLocal: true}
	result, err := client.SendHeartbeat(context.Background(), testHeartbeatInput(t))
	if err != nil {
		t.Fatal(err)
	}
	if result.CertificateInstruction == nil ||
		result.CertificateInstruction.Action != "request_csr" ||
		result.CertificateInstruction.CommonName != "Gateway.Stogas.AI" ||
		strings.Join(result.CertificateInstruction.DNSNames, ",") != "gateway.stogas.ai,api.stogas.ai" ||
		result.CertificateInstruction.OrderID != "order-1" {
		t.Fatalf("unexpected certificate instruction: %#v", result.CertificateInstruction)
	}
}

func TestSubmitCertificateCSRPostsStrictControlContract(t *testing.T) {
	generationID := strings.Repeat("a", 64)
	spkiHash := strings.Repeat("b", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/fleet/cert/csr" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["generation_id"] != generationID || body["order_id"] != "order-1" || body["tls_spki_sha256"] != spkiHash {
			t.Fatalf("unexpected CSR submission identity: %#v", body)
		}
		if body["csr_der"] != base64.RawURLEncoding.EncodeToString([]byte("csr-der")) {
			t.Fatalf("CSR DER was not base64url encoded: %#v", body)
		}
		if names := body["dns_names"].([]any); len(names) != 2 || names[0] != "gateway.stogas.ai" || names[1] != "api.stogas.ai" {
			t.Fatalf("unexpected normalized DNS names: %#v", body["dns_names"])
		}
		_, _ = w.Write([]byte(`{"generation_id":"` + generationID + `","ok":true,"order_id":"order-1"}`))
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, AllowInsecureLocal: true}
	result, err := client.SubmitCertificateCSR(context.Background(), CertificateCSRSubmission{
		CommonName:    "Gateway.Stogas.AI",
		CSRDER:        []byte("csr-der"),
		DNSNames:      []string{"Gateway.Stogas.AI", "api.stogas.ai", "gateway.stogas.ai"},
		GenerationID:  strings.ToUpper(generationID),
		OrderID:       "order-1",
		TLSSPKISHA256: strings.ToUpper(spkiHash),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.GenerationID != generationID || result.OrderID != "order-1" || !result.OK {
		t.Fatalf("unexpected CSR response: %#v", result)
	}
}

func TestSendHeartbeatValidatesInlineSecretBundle(t *testing.T) {
	generationID := strings.Repeat("d", 64)
	reportHash := strings.Repeat("e", 128)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/fleet/heartbeat" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificate_instruction": nil,
			"generation_id": generationID,
			"ok": true,
			"ready": false,
			"ready_until": nil,
			"secrets": map[string]any{
				"generation_id": generationID,
				"report_data_sha512": reportHash,
				"schema": SecretReleaseSchemaV1,
				"secrets": []map[string]string{{
					"aad_sha256": strings.Repeat("f", 64),
					"ciphertext": "Y2lwaGVydGV4dA",
					"encapsulated_key": "ZW5j",
					"key_id": "provider",
					"name": "OPENAI_API_KEY",
					"version": "1",
				}},
			},
		})
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, AllowInsecureLocal: true}
	input := testHeartbeatInput(t)
	input.Quote.ReportDataHex = reportHash
	result, err := client.SendHeartbeat(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Secrets == nil || result.Secrets.Schema != SecretReleaseSchemaV1 || len(result.Secrets.Secrets) != 1 {
		t.Fatalf("unexpected secret response: %#v", result)
	}
}

func TestClientFailsClosedForUnsafeOrMalformedControlResponses(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		call    func(Client) error
		want    string
	}{
		{
			name: "https required outside local",
			handler: func(w http.ResponseWriter, r *http.Request) {
				t.Fatal("request should not be sent")
			},
			call: func(client Client) error {
				client.AllowInsecureLocal = false
				_, err := client.SendHeartbeat(context.Background(), testHeartbeatInput(t))
				return err
			},
			want: "control url must use https",
		},
		{
			name: "control rejection reason surfaced",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"message":"Rejected confidential gateway heartbeat","reason":"unknown chip_id"}`))
			},
			call: func(client Client) error {
				_, err := client.SendHeartbeat(context.Background(), testHeartbeatInput(t))
				return err
			},
			want: "unknown chip_id",
		},
		{
			name: "unknown response field rejected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"certificate_instruction":null,"generation_id":"` + strings.Repeat("b", 64) + `","ok":true,"ready":false,"ready_until":null,"secrets":null,"extra":true}`))
			},
			call: func(client Client) error {
				_, err := client.SendHeartbeat(context.Background(), testHeartbeatInput(t))
				return err
			},
			want: "unknown field",
		},
		{
			name: "inconsistent admission lease rejected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"certificate_instruction":null,"generation_id":"` + strings.Repeat("b", 64) + `","ok":true,"ready":true,"ready_until":null,"secrets":null}`))
			},
			call: func(client Client) error {
				_, err := client.SendHeartbeat(context.Background(), testHeartbeatInput(t))
				return err
			},
			want: "readiness lease is inconsistent",
		},
		{
			name: "malformed certificate instruction rejected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"certificate_instruction":{"action":"activate_staged","cert_sha256":"not-hex","order_id":"order-1"},"generation_id":"` + strings.Repeat("b", 64) + `","ok":true,"ready":false,"ready_until":null,"secrets":null}`))
			},
			call: func(client Client) error {
				_, err := client.SendHeartbeat(context.Background(), testHeartbeatInput(t))
				return err
			},
			want: "invalid certificate hash",
		},
		{
			name: "secret plaintext-shaped response rejected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"certificate_instruction":null,"generation_id":"` + strings.Repeat("d", 64) + `","ok":true,"ready":false,"ready_until":null,"secrets":{"generation_id":"` + strings.Repeat("d", 64) + `","report_data_sha512":"` + strings.Repeat("e", 128) + `","schema":"` + SecretReleaseSchemaV1 + `","secrets":[{"aad_sha256":"` + strings.Repeat("f", 64) + `","ciphertext":"","encapsulated_key":"ZW5j","key_id":"provider","name":"OPENAI_API_KEY","version":"1"}]}}`))
			},
			call: func(client Client) error {
				input := testHeartbeatInput(t)
				input.Quote.ReportDataHex = strings.Repeat("e", 128)
				_, err := client.SendHeartbeat(context.Background(), input)
				return err
			},
			want: "secret ciphertext missing ciphertext",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()
			client := Client{BaseURL: server.URL, AllowInsecureLocal: true}
			err := tt.call(client)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func testHeartbeatInput(t *testing.T) HeartbeatInput {
	t.Helper()
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	return HeartbeatInput{
		CertExpiresAt: now.Add(90 * 24 * time.Hour),
		Health:        NodeHealth{Ready: true, SecretVersions: map[string]string{}},
		NodeID:        "node-1",
		ObservedAt:    now,
		Quote:         testSnapshot(t, now),
	}
}

func testSnapshot(t *testing.T, generatedAt time.Time) *quote.Snapshot {
	t.Helper()
	payload, err := reportdata.NewPayload(reportdata.Payload{
		CatalogHash:        strings.Repeat("2", 64),
		TLSSPKISHA256:      strings.Repeat("3", 64),
		ActiveCertSHA256:   strings.Repeat("4", 64),
		AcceptedCertSHA256: []string{strings.Repeat("4", 64)},
		HPKEPublicKey:      "aHBrZQ",
		Ed25519PublicKey:   "ZWQyNTUxOQ",
		Drand: reportdata.Drand{
			Round:      10,
			Randomness: strings.Repeat("5", 64),
			Signature:  strings.Repeat("6", 96),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := reportdata.HashHex(payload)
	if err != nil {
		t.Fatal(err)
	}
	return &quote.Snapshot{
		Payload:       payload,
		ReportDataHex: hash,
		Quote:         []byte("quote-bytes"),
		GeneratedAt:   generatedAt,
	}
}
