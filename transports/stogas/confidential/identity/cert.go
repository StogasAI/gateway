package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxCertificateChainBytes = 32 * 1024
const maxCertificateChainLength = 16

type CertificateStore struct {
	mu                sync.RWMutex
	material          *Material
	verificationRoots *x509.CertPool
	certificate       *tls.Certificate
}
type CertificateState struct {
	ActiveCertSHA256 string
	ExpiresAt        time.Time
	NotBefore        time.Time
}
type CSRInput struct {
	CommonName string
	DNSNames   []string
}

func NewBootCertificateStore(material *Material, roots *x509.CertPool) (*CertificateStore, error) {
	if material == nil || material.TLSPrivateKey == nil {
		return nil, errors.New("TLS identity key is required")
	}
	if roots != nil {
		roots = roots.Clone()
	}
	return &CertificateStore{material: material, verificationRoots: roots}, nil
}

// InstallBootChain appraises the complete chain before replacing the certificate.
// The TLS key stays in this guest; renewal does not alter boot/session identity.
func (s *CertificateStore) InstallBootChain(chain []byte, hostname string) (CertificateState, error) {
	if s == nil || s.material == nil || hostname == "" {
		return CertificateState{}, errors.New("invalid certificate installation")
	}
	certs, err := parseCertificateChain(chain)
	if err != nil {
		return CertificateState{}, err
	}
	leaf := certs[0]
	if leaf.IsCA {
		return CertificateState{}, errors.New("server certificate cannot be a CA")
	}
	spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return CertificateState{}, err
	}
	if sha256.Sum256(spki) != s.material.TLSSPKISHA256 {
		return CertificateState{}, errors.New("certificate must reuse the guest TLS key")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{DNSName: hostname, Intermediates: intermediates, Roots: s.verificationRoots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return CertificateState{}, err
	}
	der := make([][]byte, len(certs))
	for i, cert := range certs {
		der[i] = cert.Raw
	}
	certificate := &tls.Certificate{Certificate: der, PrivateKey: s.material.TLSPrivateKey, Leaf: leaf}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certificate = certificate
	return s.stateLocked(), nil
}
func (s *CertificateStore) State() CertificateState {
	if s == nil {
		return CertificateState{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stateLocked()
}
func (s *CertificateStore) stateLocked() CertificateState {
	if s.certificate == nil {
		return CertificateState{}
	}
	leaf := s.certificate.Leaf
	return CertificateState{ActiveCertSHA256: CertSHA256Hex(leaf.Raw), ExpiresAt: leaf.NotAfter, NotBefore: leaf.NotBefore}
}
func (s *CertificateStore) ActiveTLSCertificate() (tls.Certificate, bool) {
	if s == nil {
		return tls.Certificate{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.certificate == nil {
		return tls.Certificate{}, false
	}
	result := *s.certificate
	result.Certificate = cloneDERChain(result.Certificate)
	result.Leaf = nil // Do not expose mutable parsed state retained by the store.
	return result, true
}
func (s *CertificateStore) CreateCSR(input CSRInput) ([]byte, error) {
	if s == nil || s.material == nil || s.material.TLSPrivateKey == nil {
		return nil, errors.New("certificate store is not initialized")
	}
	names := normalizeNames(input.DNSNames)
	commonName := strings.TrimSpace(input.CommonName)
	if commonName == "" && len(names) == 0 {
		return nil, errors.New("CSR requires a service name")
	}
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}, DNSNames: names}, s.material.TLSPrivateKey)
}

func parseCertificateChain(input []byte) ([]*x509.Certificate, error) {
	if len(input) == 0 {
		return nil, errors.New("certificate chain is required")
	}
	if len(input) > maxCertificateChainBytes {
		return nil, errors.New("certificate chain is too large")
	}
	rest := input
	var certs []*x509.Certificate
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("certificate chain contains unexpected %q PEM block", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate PEM block: %w", err)
		}
		certs = append(certs, cert)
		if len(certs) > maxCertificateChainLength {
			return nil, errors.New("certificate chain contains too many certificates")
		}
		rest = next
	}
	if len(certs) == 0 {
		cert, err := x509.ParseCertificate(input)
		if err != nil {
			return nil, fmt.Errorf("parse certificate chain: %w", err)
		}
		certs = append(certs, cert)
	} else if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("certificate chain contains trailing non-PEM data")
	}
	return certs, nil
}

func normalizeNames(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func cloneDERChain(chain [][]byte) [][]byte {
	out := make([][]byte, 0, len(chain))
	for _, cert := range chain {
		out = append(out, append([]byte(nil), cert...))
	}
	return out
}
