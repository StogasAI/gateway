package awsauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/maximhq/bifrost/transports/stogas/federation"
)

const organization = "01990000-0000-7000-8000-000000000001"

func testIssuer(t *testing.T) (*federation.Issuer, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := federation.NewIssuer(base64.StdEncoding.EncodeToString(der), "https://app.stogas.ai")
	if err != nil {
		t.Fatal(err)
	}
	return issuer, &key.PublicKey
}

func TestAssumeExchangesTheOrganizationTokenForRoleCredentials(t *testing.T) {
	issuer, public := testIssuer(t)
	credential := Credential{OrganizationID: organization, Region: "us-east-1", RoleARN: "arn:aws:iam::123456789012:role/stogas"}
	var form url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(body))
		// The answer as STS documents it.
		_, _ = io.WriteString(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <SubjectFromWebIdentityToken>organization:`+organization+`</SubjectFromWebIdentityToken>
    <Audience>sts.amazonaws.com</Audience>
    <Credentials>
      <SessionToken>session-token</SessionToken>
      <SecretAccessKey>secret-key</SecretAccessKey>
      <Expiration>2026-11-16T10:00:00Z</Expiration>
      <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`)
	}))
	defer server.Close()
	token, err := assume(context.Background(), server.Client(), issuer, server.URL, credential, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC); !token.ExpiresAt.Equal(want) {
		t.Fatalf("expires %s", token.ExpiresAt)
	}
	if token.Value != `{"accessKeyId":"ASIAEXAMPLE","secretAccessKey":"secret-key","sessionToken":"session-token"}` {
		t.Fatalf("credentials %s", token.Value)
	}
	if form.Get("Action") != "AssumeRoleWithWebIdentity" || form.Get("RoleArn") != credential.RoleARN ||
		form.Get("RoleSessionName") != "stogas-"+organization || form.Get("DurationSeconds") != "3600" {
		t.Fatalf("request %v", form)
	}
	// AWS accepts the token only for this organization's issuer and audience.
	if _, err := jwt.Parse(form.Get("WebIdentityToken"), func(*jwt.Token) (any, error) { return public, nil },
		jwt.WithAudience(federation.AudienceAWS), jwt.WithSubject("organization:"+organization),
		jwt.WithIssuer("https://app.stogas.ai/api/federation/"+organization)); err != nil {
		t.Fatalf("identity token: %v", err)
	}
}

func TestAssumeTellsARefusalFromAnOutage(t *testing.T) {
	issuer, _ := testIssuer(t)
	credential := Credential{OrganizationID: organization, Region: "us-east-1", RoleARN: "arn:aws:iam::123456789012:role/stogas"}
	failure := func(code string) string {
		return `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>` + code + `</Code><Message>m</Message></Error></ErrorResponse>`
	}
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"the role does not trust the token", http.StatusForbidden, failure("AccessDenied"), ErrCredential},
		{"AWS cannot verify the token", http.StatusBadRequest, failure("InvalidIdentityToken"), ErrCredential},
		{"the role rejects a claim", http.StatusForbidden, failure("IDPRejectedClaim"), ErrCredential},
		{"the account disabled the Region", http.StatusForbidden, failure("RegionDisabledException"), ErrCredential},
		{"AWS cannot read the issuer's keys", http.StatusBadRequest, failure("IDPCommunicationError"), ErrUnavailable},
		{"throttled", http.StatusBadRequest, failure("Throttling"), ErrUnavailable},
		{"STS fails", http.StatusInternalServerError, failure("InternalFailure"), ErrUnavailable},
		{"an answer that is not STS's", http.StatusForbidden, "<html>blocked</html>", ErrUnavailable},
		{"credentials are missing", http.StatusOK, "<AssumeRoleWithWebIdentityResponse/>", ErrUnavailable},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(test.status)
			_, _ = io.WriteString(w, test.body)
		}))
		_, err := assume(context.Background(), server.Client(), issuer, server.URL, credential, time.Now())
		server.Close()
		if !errors.Is(err, test.want) {
			t.Errorf("%s: error %v, want %v", test.name, err, test.want)
		}
	}
	// A gateway without a signing key cannot sign in, which is no fault of the credential.
	if _, err := assume(context.Background(), http.DefaultClient, nil, "https://sts.invalid/", credential, time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("without a key: %v", err)
	}
}
