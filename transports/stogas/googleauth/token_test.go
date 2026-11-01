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
