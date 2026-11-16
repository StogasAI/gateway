package federation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const organization = "01990000-0000-7000-8000-000000000001"

func testIssuer(t *testing.T) (*Issuer, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewIssuer(base64.StdEncoding.EncodeToString(der), "https://app.stogas.ai")
	if err != nil {
		t.Fatal(err)
	}
	return issuer, &key.PublicKey
}

func TestTokenStatesOneOrganizationToOneAudience(t *testing.T) {
	issuer, public := testIssuer(t)
	now := time.Now().Truncate(time.Second)
	signed, err := issuer.Token(organization, AudienceAWS, now)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(signed, claims, func(*jwt.Token) (any, error) { return public, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(AudienceAWS),
		jwt.WithIssuer("https://app.stogas.ai/api/federation/"+organization), jwt.WithSubject("organization:"+organization))
	if err != nil || !token.Valid {
		t.Fatalf("token does not verify: %v", err)
	}
	// Every cloud documents the audience as one string and reads the key by its ID.
	if audience, ok := claims["aud"].(string); !ok || audience != AudienceAWS {
		t.Fatalf("audience %#v", claims["aud"])
	}
	if token.Header["kid"] != KeyID(public) {
		t.Fatalf("key ID %v", token.Header["kid"])
	}
	expires, _ := claims.GetExpirationTime()
	if got := expires.Sub(now); got != 5*time.Minute {
		t.Fatalf("token lives %s", got)
	}
	other, err := issuer.Token(organization, AudienceAWS, now)
	if err != nil || other == signed {
		t.Fatal("two tokens share an ID")
	}
}

func TestTokenRefusesAnythingButAnOrganizationID(t *testing.T) {
	issuer, _ := testIssuer(t)
	for _, id := range []string{"", "org", organization + "/../other", "01990000-0000-7000-8000-00000000000G"} {
		if _, err := issuer.Token(id, AudienceAzure, time.Now()); err == nil {
			t.Errorf("signed a token for %q", id)
		}
	}
	if _, err := issuer.Token(organization, "", time.Now()); err == nil {
		t.Error("signed a token for no audience")
	}
	var missing *Issuer
	if _, err := missing.Token(organization, AudienceAzure, time.Now()); err != ErrUnavailable {
		t.Errorf("a gateway without a key answered %v", err)
	}
}

func TestNewIssuerRefusesWeakOrForeignKeys(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(weak)
	for name, key := range map[string]string{
		"1024 bits":  base64.StdEncoding.EncodeToString(der),
		"not base64": "-----BEGIN PRIVATE KEY-----",
		"not a key":  base64.StdEncoding.EncodeToString([]byte("secret")),
	} {
		if _, err := NewIssuer(key, "https://app.stogas.ai"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The example key and thumbprint of RFC 7638, section 3.1.
func TestKeyIDIsTheRFC7638Thumbprint(t *testing.T) {
	modulus, err := base64.RawURLEncoding.DecodeString("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
	if err != nil {
		t.Fatal(err)
	}
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: 65537}
	if got := KeyID(key); got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint %s", got)
	}
}
