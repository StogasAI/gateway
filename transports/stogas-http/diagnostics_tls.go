package stogashttp

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"
)

const privateDiagnosticsPort = "5187"

// The bootstrap release supplies only the monitor's public key pin. The
// monitor keeps its private key; no host-provided value can authorize a client.
func (s *Server) diagnosticsTLSConfig() (*tls.Config, error) {
	pin, err := hex.DecodeString(s.config.DiagnosticsClientSPKISHA256)
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("diagnostics client SPKI pin is invalid")
	}
	var expected [sha256.Size]byte
	copy(expected[:], pin)
	config := s.confidentialTLSConfig()
	config.MinVersion = tls.VersionTLS13
	config.ClientAuth = tls.RequireAnyClientCert
	config.VerifyConnection = func(state tls.ConnectionState) error {
		return verifyDiagnosticsClient(state, expected, time.Now())
	}
	return config, nil
}

func verifyDiagnosticsClient(state tls.ConnectionState, expected [sha256.Size]byte, now time.Time) error {
	if len(state.PeerCertificates) != 1 {
		return errors.New("diagnostics requires one pinned client certificate")
	}
	certificate := state.PeerCertificates[0]
	if sha256.Sum256(certificate.RawSubjectPublicKeyInfo) != expected {
		return errors.New("diagnostics client key is not authorized")
	}
	// Treat the pinned certificate as a direct trust anchor. Standard X.509
	// verification still checks validity, critical extensions, and client use.
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	_, err := certificate.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}
