package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
)

// testLogger is a minimal logger for tests that implements schemas.Logger.
type testLogger struct{}

func (testLogger) Debug(string, ...any)                   {}
func (testLogger) Info(string, ...any)                    {}
func (testLogger) Warn(string, ...any)                    {}
func (testLogger) Error(string, ...any)                   {}
func (testLogger) Fatal(string, ...any)                   {}
func (testLogger) SetLevel(schemas.LogLevel)              {}
func (testLogger) SetOutputType(schemas.LoggerOutputType) {}
func (testLogger) LogHTTPRequest(schemas.LogLevel, string) schemas.LogEventBuilder {
	return schemas.NoopLogEvent
}

// validTestCertPEM returns a minimal valid PEM-encoded CA certificate for testing.
func validTestCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	block := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return string(pem.EncodeToMemory(block))
}

func TestConfigureTLS_ReturnsUnchangedWhenNeitherSet(t *testing.T) {
	client := &fasthttp.Client{}
	logger := testLogger{}

	result := ConfigureTLS(client, schemas.NetworkConfig{}, logger)

	if result != client {
		t.Error("ConfigureTLS should return the same client when neither InsecureSkipVerify nor CACertPEM is set")
	}
	if client.TLSConfig != nil {
		t.Error("TLSConfig should remain nil when no TLS options are set")
	}
}

func TestConfigureTLSRequiresOnlyHybridPostQuantumKeyExchange(t *testing.T) {
	client := &fasthttp.Client{}
	result := ConfigureTLS(
		client,
		schemas.NetworkConfig{RequirePostQuantumTLS: true},
		testLogger{},
	)

	if result != client || client.TLSConfig == nil {
		t.Fatal("ConfigureTLS did not install the required TLS config")
	}
	if client.TLSConfig.MinVersion != tls.VersionTLS13 || client.TLSConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS versions = %x..%x, want TLS 1.3 only", client.TLSConfig.MinVersion, client.TLSConfig.MaxVersion)
	}
	if len(client.TLSConfig.CurvePreferences) != 1 || client.TLSConfig.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Fatalf("TLS curves = %v, want only X25519MLKEM768", client.TLSConfig.CurvePreferences)
	}
	if err := client.TLSConfig.VerifyConnection(tls.ConnectionState{
		Version: tls.VersionTLS13,
		CurveID: tls.X25519MLKEM768,
	}); err != nil {
		t.Fatalf("hybrid TLS state was rejected: %v", err)
	}
	if err := client.TLSConfig.VerifyConnection(tls.ConnectionState{
		Version: tls.VersionTLS13,
		CurveID: tls.X25519,
	}); err == nil {
		t.Fatal("classical TLS state was accepted")
	}
}

func TestConfigureTLSCanRequireTLS13WithoutForcingHybridKeyExchange(t *testing.T) {
	client := &fasthttp.Client{}
	result := ConfigureTLS(
		client,
		schemas.NetworkConfig{RequireTLS13: true},
		testLogger{},
	)

	if result != client || client.TLSConfig == nil {
		t.Fatal("ConfigureTLS did not install the required TLS config")
	}
	if client.TLSConfig.MinVersion != tls.VersionTLS13 || client.TLSConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS versions = %x..%x, want TLS 1.3 only", client.TLSConfig.MinVersion, client.TLSConfig.MaxVersion)
	}
	if len(client.TLSConfig.CurvePreferences) != 0 {
		t.Fatalf("TLS 1.3 policy unexpectedly forced curves %v", client.TLSConfig.CurvePreferences)
	}
	if client.TLSConfig.VerifyConnection != nil {
		t.Fatal("TLS 1.3 policy unexpectedly installed a hybrid-only verifier")
	}
}

func TestConfigureTLS_SetsInsecureSkipVerify(t *testing.T) {
	client := &fasthttp.Client{}
	logger := testLogger{}

	result := ConfigureTLS(client, schemas.NetworkConfig{InsecureSkipVerify: true}, logger)

	if result != client {
		t.Error("ConfigureTLS should return the same client")
	}
	if client.TLSConfig == nil {
		t.Fatal("TLSConfig should be set when InsecureSkipVerify is true")
	}
	if !client.TLSConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
}

func TestConfigureTLS_AppliesCACertPEM(t *testing.T) {
	client := &fasthttp.Client{}
	logger := testLogger{}
	caPEM := validTestCertPEM(t)

	result := ConfigureTLS(client, schemas.NetworkConfig{CACertPEM: schemas.NewSecretVar(caPEM)}, logger)

	if result != client {
		t.Error("ConfigureTLS should return the same client")
	}
	if client.TLSConfig == nil {
		t.Fatal("TLSConfig should be set when CACertPEM is provided")
	}
	if client.TLSConfig.RootCAs == nil {
		t.Error("RootCAs should be set when CACertPEM is provided")
	}
}

func TestConfigureTLS_HandlesInvalidCACertPEM(t *testing.T) {
	client := &fasthttp.Client{}
	logger := testLogger{}

	result := ConfigureTLS(client, schemas.NetworkConfig{CACertPEM: schemas.NewSecretVar("not-valid-pem")}, logger)

	if result != client {
		t.Error("ConfigureTLS should return the same client even when CACertPEM is invalid")
	}
	// Invalid PEM logs warning and skips RootCAs; TLSConfig may still be set with MinVersion
	if client.TLSConfig != nil && client.TLSConfig.RootCAs != nil {
		t.Error("RootCAs should not be set when CACertPEM is invalid")
	}
}

func TestConfigureTLS_MergesWithExistingTLSConfig(t *testing.T) {
	// Simulate client that already has TLSConfig from ConfigureProxy
	existingRootCAs, _ := x509.SystemCertPool()
	if existingRootCAs == nil {
		existingRootCAs = x509.NewCertPool()
	}
	client := &fasthttp.Client{
		TLSConfig: &tls.Config{
			RootCAs:    existingRootCAs,
			MinVersion: tls.VersionTLS12,
		},
	}
	logger := testLogger{}
	caPEM := validTestCertPEM(t)

	result := ConfigureTLS(client, schemas.NetworkConfig{CACertPEM: schemas.NewSecretVar(caPEM)}, logger)

	if result != client {
		t.Error("ConfigureTLS should return the same client")
	}
	if client.TLSConfig == nil {
		t.Fatal("TLSConfig should remain set")
	}
	if client.TLSConfig.RootCAs == nil {
		t.Error("RootCAs should be set (merged with existing)")
	}
}

func TestConfigureTLS_InsecureSkipVerifyAndCACertPEM(t *testing.T) {
	client := &fasthttp.Client{}
	logger := testLogger{}
	caPEM := validTestCertPEM(t)

	result := ConfigureTLS(client, schemas.NetworkConfig{
		InsecureSkipVerify: true,
		CACertPEM:          schemas.NewSecretVar(caPEM),
	}, logger)

	if result != client {
		t.Error("ConfigureTLS should return the same client")
	}
	if client.TLSConfig == nil {
		t.Fatal("TLSConfig should be set")
	}
	if !client.TLSConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true when both options are set")
	}
	if client.TLSConfig.RootCAs == nil {
		t.Error("RootCAs should be set when CACertPEM is provided")
	}
}
