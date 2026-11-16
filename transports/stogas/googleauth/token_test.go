package googleauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/maximhq/bifrost/transports/stogas/federation"
)

func testKey(t *testing.T, bits int) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, base64.StdEncoding.EncodeToString(der)
}

func TestExchangeSignsTheAssertionAndReadsTheToken(t *testing.T) {
	key, encoded := testKey(t, 2048)
	now := time.Unix(1_800_000_000, 0)
	var assertion string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		assertion = form.Get("assertion")
		_, _ = io.WriteString(w, `{"access_token":"ya29.token","expires_in":3599,"token_type":"Bearer"}`)
	}))
	defer server.Close()
	credential := Credential{ClientEmail: "runner@project.iam.gserviceaccount.com", PrivateKeyID: "key-1", PrivateKey: encoded}
	token, err := exchange(context.Background(), server.Client(), server.URL, credential, now)
	if err != nil || token.Value != "ya29.token" || !token.ExpiresAt.Equal(now.Add(3599*time.Second)) {
		t.Fatalf("token %+v, error %v", token, err)
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion %q is not a JWT", assertion)
	}
	var header map[string]string
	var claims map[string]any
	headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if json.Unmarshal(headerJSON, &header) != nil || json.Unmarshal(claimsJSON, &claims) != nil {
		t.Fatal("assertion is not JSON")
	}
	if header["alg"] != "RS256" || header["kid"] != "key-1" || claims["iss"] != credential.ClientEmail ||
		claims["aud"] != server.URL || claims["scope"] != Scope ||
		claims["iat"] != float64(now.Unix()) || claims["exp"] != float64(now.Add(time.Hour).Unix()) {
		t.Fatalf("assertion header %v, claims %v", header, claims)
	}
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatal("assertion signature does not verify")
	}
}

func TestExchangeSeparatesRejectedKeysFromOutages(t *testing.T) {
	_, encoded := testKey(t, 2048)
	credential := Credential{ClientEmail: "runner@project.iam.gserviceaccount.com", PrivateKeyID: "key-1", PrivateKey: encoded}
	for _, test := range []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusBadRequest, `{"error":"invalid_grant"}`, ErrCredential},
		{http.StatusUnauthorized, `{}`, ErrCredential},
		{http.StatusForbidden, `{}`, ErrCredential},
		{http.StatusInternalServerError, `{}`, ErrUnavailable},
		{http.StatusOK, `{"access_token":"","expires_in":3599,"token_type":"Bearer"}`, ErrUnavailable},
		{http.StatusOK, `{"access_token":"t","expires_in":3599,"token_type":"MAC"}`, ErrUnavailable},
		{http.StatusOK, `{"access_token":"t","expires_in":0,"token_type":"Bearer"}`, ErrUnavailable},
		{http.StatusOK, `not json`, ErrUnavailable},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(test.status)
			_, _ = io.WriteString(w, test.body)
		}))
		_, err := exchange(context.Background(), server.Client(), server.URL, credential, time.Now())
		server.Close()
		if !errors.Is(err, test.want) {
			t.Fatalf("status %d body %s: error %v, want %v", test.status, test.body, err, test.want)
		}
	}
}

func TestParsePrivateKeyAcceptsOnlyLargeRSAKeys(t *testing.T) {
	if _, encoded := testKey(t, 2048); func() error { _, err := ParsePrivateKey(encoded); return err }() != nil {
		t.Fatal("2048-bit RSA key rejected")
	}
	_, small := testKey(t, 1024)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	for _, encoded := range []string{small, base64.StdEncoding.EncodeToString(ecDER), "not base64!", base64.StdEncoding.EncodeToString([]byte("garbage"))} {
		if _, err := ParsePrivateKey(encoded); !errors.Is(err, ErrCredential) {
			t.Fatalf("key %.16q accepted", encoded)
		}
	}
}

func testIssuer(t *testing.T) (*federation.Issuer, *rsa.PublicKey) {
	t.Helper()
	key, encoded := testKey(t, 2048)
	issuer, err := federation.NewIssuer(encoded, "https://app.stogas.ai")
	if err != nil {
		t.Fatal(err)
	}
	return issuer, &key.PublicKey
}

const (
	testOrganization = "01990000-0000-7000-8000-000000000001"
	testProvider     = "projects/123456789012/locations/global/workloadIdentityPools/stogas/providers/stogas"
)

func TestFederateExchangesTheOrganizationTokenAndActsAsTheServiceAccount(t *testing.T) {
	issuer, public := testIssuer(t)
	now := time.Unix(1_800_000_000, 0)
	var form url.Values
	var impersonation struct{ path, authorization, body string }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/v1/token" {
			form, _ = url.ParseQuery(string(body))
			_, _ = io.WriteString(w, `{"access_token":"ya29.federated","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}`)
			return
		}
		impersonation.path, impersonation.authorization, impersonation.body = r.URL.Path, r.Header.Get("Authorization"), string(body)
		_, _ = io.WriteString(w, `{"accessToken":"ya29.account","expireTime":"2027-01-15T09:00:00Z"}`)
	}))
	defer server.Close()
	direct := Credential{OrganizationID: testOrganization, Provider: testProvider}
	token, err := federate(context.Background(), server.Client(), issuer, server.URL+"/v1/token", server.URL+"/accounts/", direct, now)
	if err != nil || token.Value != "ya29.federated" || !token.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("token %+v, error %v", token, err)
	}
	if impersonation.path != "" {
		t.Fatal("a credential without a service account asked for one")
	}
	// Google names the provider with a scheme in the token and without one in the exchange.
	if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
		form.Get("audience") != "//iam.googleapis.com/"+testProvider ||
		form.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:jwt" ||
		form.Get("requested_token_type") != "urn:ietf:params:oauth:token-type:access_token" || form.Get("scope") != Scope {
		t.Fatalf("exchange %v", form)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience("https://iam.googleapis.com/"+testProvider),
		jwt.WithSubject("organization:"+testOrganization), jwt.WithIssuer("https://app.stogas.ai/api/federation/"+testOrganization),
		jwt.WithTimeFunc(func() time.Time { return now }))
	if _, err := parser.Parse(form.Get("subject_token"), func(*jwt.Token) (any, error) { return public, nil }); err != nil {
		t.Fatalf("subject token: %v", err)
	}

	account := Credential{OrganizationID: testOrganization, Provider: testProvider, ClientEmail: "runner@project.iam.gserviceaccount.com"}
	token, err = federate(context.Background(), server.Client(), issuer, server.URL+"/v1/token", server.URL+"/accounts/", account, now)
	if err != nil || token.Value != "ya29.account" || !token.ExpiresAt.Equal(time.Date(2027, 1, 15, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("token %+v, error %v", token, err)
	}
	if impersonation.path != "/accounts/runner@project.iam.gserviceaccount.com:generateAccessToken" ||
		impersonation.authorization != "Bearer ya29.federated" || impersonation.body != `{"scope":["`+Scope+`"]}` {
		t.Fatalf("impersonation %+v", impersonation)
	}
}

func TestFederateTellsARefusalFromAnOutage(t *testing.T) {
	issuer, _ := testIssuer(t)
	credential := Credential{OrganizationID: testOrganization, Provider: testProvider, ClientEmail: "runner@project.iam.gserviceaccount.com"}
	for _, test := range []struct {
		name            string
		exchange, actAs int
		want            error
	}{
		{"the pool does not accept the token", http.StatusBadRequest, 0, ErrProvider},
		{"the identity may not act as the account", http.StatusOK, http.StatusForbidden, ErrServiceAccount},
		{"the account does not exist", http.StatusOK, http.StatusNotFound, ErrServiceAccount},
		{"each names a refusal", http.StatusBadRequest, 0, ErrCredential},
		{"each names a refusal", http.StatusOK, http.StatusForbidden, ErrCredential},
		{"the exchange fails", http.StatusServiceUnavailable, 0, ErrUnavailable},
		{"the account service fails", http.StatusOK, http.StatusInternalServerError, ErrUnavailable},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/token" {
				w.WriteHeader(test.exchange)
				_, _ = io.WriteString(w, `{"access_token":"ya29.federated","expires_in":3600}`)
				return
			}
			w.WriteHeader(test.actAs)
		}))
		_, err := federate(context.Background(), server.Client(), issuer, server.URL+"/v1/token", server.URL+"/accounts/", credential, time.Now())
		server.Close()
		if !errors.Is(err, test.want) {
			t.Errorf("%s: error %v, want %v", test.name, err, test.want)
		}
	}
	if _, err := federate(context.Background(), http.DefaultClient, nil, "https://sts.invalid/", "https://iam.invalid/", credential, time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("without a key: %v", err)
	}
}
