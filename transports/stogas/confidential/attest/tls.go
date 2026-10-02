package attest

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"
)

const NativeALPNPrefix = "stogas-attest-v1."

var ErrAttestationALPN = errors.New("invalid native attestation ALPN")

type setupDeadlineKey struct{}

// WithSetupDeadline records the absolute setup deadline when a connection is
// accepted. net/http's ConnContext can use it without canceling later requests
// on that reusable connection. The TLS callback creates the short-lived timer.
func WithSetupDeadline(parent context.Context, deadline time.Time) context.Context {
	if previous, ok := parent.Value(setupDeadlineKey{}).(time.Time); ok && previous.Before(deadline) {
		deadline = previous
	}
	return context.WithValue(parent, setupDeadlineKey{}, deadline)
}

func setupDeadline(ctx context.Context) (time.Time, bool) {
	deadline, ok := ctx.Deadline()
	if recorded, exists := ctx.Value(setupDeadlineKey{}).(time.Time); exists && !recorded.IsZero() {
		if !ok || recorded.Before(deadline) {
			deadline, ok = recorded, true
		}
	}
	return deadline, ok
}

// NativeALPN returns the private marker offered alongside normal HTTP ALPN.
func NativeALPN(challenge [32]byte) string {
	return NativeALPNPrefix + base64.RawURLEncoding.EncodeToString(challenge[:])
}

func parseNativeALPN(protocols []string) (challenge [32]byte, requested bool, err error) {
	for _, protocol := range protocols {
		if !strings.HasPrefix(protocol, "stogas-attest") {
			continue
		}
		if requested || !strings.HasPrefix(protocol, NativeALPNPrefix) || len(protocol) != len(NativeALPNPrefix)+43 {
			return challenge, true, ErrAttestationALPN
		}
		decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(protocol[len(NativeALPNPrefix):])
		if decodeErr != nil || len(decoded) != len(challenge) {
			return challenge, true, ErrAttestationALPN
		}
		copy(challenge[:], decoded)
		requested = true
	}
	if requested && !slices.Contains(protocols, "h2") && !slices.Contains(protocols, "http/1.1") {
		return challenge, true, ErrAttestationALPN
	}
	return challenge, requested, nil
}

// NativeCertificateIssuer constructs a fresh ML-DSA-65 signer and its attested
// certificate from this handshake's locally parsed challenge. It is called only
// after Go validates TLS 1.3's key exchange, never by GetConfigForClient.
type NativeCertificateIssuer func(context.Context, [32]byte) (*tls.Certificate, error)

// ConfigureTLS preserves the ordinary listener's certificate handling and adds
// strict native attestation on its private ALPN marker. No mutable config or
// certificate is shared between attested handshakes. The issuer owns evidence
// creation; admission must also be checked by each HTTP request handler.
func ConfigureTLS(base *tls.Config, admitted func() bool, issue NativeCertificateIssuer) (*tls.Config, error) {
	if base == nil || admitted == nil || issue == nil || base.GetConfigForClient != nil {
		return nil, errors.New("native attestation requires a base TLS config, admission and certificate issuer")
	}
	config := base.Clone()
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if !admitted() {
			return nil, errors.New("gateway admission is closed")
		}
		challenge, requested, err := parseNativeALPN(hello.SupportedProtos)
		if err != nil || !requested {
			return nil, err
		}
		deadline, bounded := setupDeadline(hello.Context())
		if !bounded {
			return nil, errors.New("native attestation requires a setup context deadline")
		}
		if !time.Now().Before(deadline) {
			return nil, context.DeadlineExceeded
		}
		strict := base.Clone()
		strict.MinVersion, strict.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
		strict.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
		strict.NextProtos = []string{"h2", "http/1.1"}
		strict.Certificates = nil
		strict.NameToCertificate = nil
		strict.SessionTicketsDisabled = true
		strict.WrapSession, strict.UnwrapSession = nil, nil
		strict.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			ctx, cancel := context.WithDeadline(hello.Context(), deadline)
			defer cancel()
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !admitted() {
				return nil, errors.New("gateway admission is closed")
			}
			if !slices.Contains(hello.SignatureSchemes, tls.MLDSA65) {
				return nil, errors.New("native attestation requires ML-DSA-65 handshake signatures")
			}
			certificate, err := issue(ctx, challenge)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return certificate, err
		}
		return strict, nil
	}
	return config, nil
}
