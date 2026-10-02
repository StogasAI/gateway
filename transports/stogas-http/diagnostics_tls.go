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

// Provisioning supplies the observer and actuator public pins. Their private
// keys remain outside the guest; host input cannot authorize a client.
func (s *Server) diagnosticsTLSConfig() (*tls.Config, error) {
	pin, err := hex.DecodeString(s.config.DiagnosticsClientSPKISHA256)
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("diagnostics client SPKI pin is invalid")
	}
	var expected [sha256.Size]byte
	copy(expected[:], pin)
	drainPin, err := hex.DecodeString(s.config.DrainClientSPKISHA256)
	if err != nil || len(drainPin) != sha256.Size || s.config.DrainClientSPKISHA256 == s.config.DiagnosticsClientSPKISHA256 {
		return nil, errors.New("a distinct drain client SPKI pin is required")
	}
	var drainExpected [sha256.Size]byte
	copy(drainExpected[:], drainPin)
	config := s.ordinaryTLSConfig()
	config.MinVersion = tls.VersionTLS13
	config.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	config.ClientAuth = tls.RequireAnyClientCert
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 1 && sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo) == drainExpected {
			return verifyDiagnosticsClient(state, drainExpected, time.Now())
		}
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
