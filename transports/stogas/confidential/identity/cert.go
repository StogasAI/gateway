package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"
)

type CertificateStore struct {
	mu         sync.RWMutex
	material   *Material
	activeHash string
	accepted   []string
	expiresAt  time.Time
	activeDER  [][]byte
	staged     *stagedCertificate
}

type CertificateState struct {
	ActiveCertSHA256   string
	AcceptedCertSHA256 []string
	ExpiresAt          time.Time
}

type CSRInput struct {
	CommonName string
	DNSNames   []string
}

type stagedCertificate struct {
	hash      string
	chainDER  [][]byte
	expiresAt time.Time
}

func NewCertificateStore(material *Material, activeHash string, accepted []string, expiresAt time.Time) (*CertificateStore, error) {
	if material == nil || material.TLSPrivateKey == nil {
		return nil, errors.New("tls identity key is required")
	}
	activeHash = strings.ToLower(strings.TrimSpace(activeHash))
	if err := validateSHA256Hex("active certificate hash", activeHash); err != nil {
		return nil, err
	}
	var err error
	accepted, err = normalizeHashes(accepted)
	if err != nil {
		return nil, err
	}
	if !containsHash(accepted, activeHash) {
		return nil, errors.New("accepted certificate hashes must include active certificate hash")
	}
	return &CertificateStore{
		material:   material,
		activeHash: activeHash,
		accepted:   accepted,
		expiresAt:  expiresAt.UTC(),
	}, nil
}

func NewProvisionalCertificateStore(material *Material, now time.Time) (*CertificateStore, error) {
	if material == nil || material.TLSPrivateKey == nil {
		return nil, errors.New("tls identity key is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	notAfter := now.UTC().Add(24 * time.Hour)
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generate provisional certificate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "stogas-confidential-provisional",
		},
		NotBefore:             now.UTC().Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&material.TLSPrivateKey.PublicKey,
		material.TLSPrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("create provisional certificate: %w", err)
	}
	hash := CertSHA256Hex(der)
	return &CertificateStore{
		material:   material,
		activeHash: hash,
		accepted:   []string{hash},
		expiresAt:  notAfter,
		activeDER:  [][]byte{append([]byte(nil), der...)},
	}, nil
}

func (s *CertificateStore) State() CertificateState {
	if s == nil {
		return CertificateState{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return CertificateState{
		ActiveCertSHA256:   s.activeHash,
		AcceptedCertSHA256: append([]string(nil), s.accepted...),
		ExpiresAt:          s.expiresAt,
	}
}

func (s *CertificateStore) CreateCSR(input CSRInput) ([]byte, error) {
	if s == nil || s.material == nil || s.material.TLSPrivateKey == nil {
		return nil, errors.New("certificate store is not initialized")
	}
	dnsNames := normalizeNames(input.DNSNames)
	commonName := strings.TrimSpace(input.CommonName)
	if commonName == "" && len(dnsNames) == 0 {
		return nil, errors.New("csr requires a common name or DNS SAN")
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: dnsNames,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, s.material.TLSPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate signing request: %w", err)
	}
	return csrDER, nil
}

func (s *CertificateStore) StageRenewedChain(chain []byte) (CertificateState, error) {
	if s == nil || s.material == nil {
		return CertificateState{}, errors.New("certificate store is not initialized")
	}
	certs, err := parseCertificateChain(chain)
	if err != nil {
		return CertificateState{}, err
	}
	leaf := certs[0]
	spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return CertificateState{}, fmt.Errorf("marshal renewed certificate spki: %w", err)
	}
	if SHA256Hex(spki) != s.material.TLSSPKISHA256 {
		return CertificateState{}, errors.New("renewed certificate must reuse the existing TLS public key")
	}
	hash := CertSHA256Hex(leaf.Raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	if hash == s.activeHash {
		return CertificateState{}, errors.New("renewed certificate hash must differ from active certificate hash")
	}
	chainDER := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		chainDER = append(chainDER, append([]byte(nil), cert.Raw...))
	}
	s.staged = &stagedCertificate{hash: hash, chainDER: chainDER, expiresAt: leaf.NotAfter.UTC()}
	accepted, err := normalizeHashes(append(s.accepted, hash))
	if err != nil {
		return CertificateState{}, err
	}
	s.accepted = accepted
	return s.stateLocked(), nil
}

func (s *CertificateStore) ActivateStaged(hash string) (CertificateState, error) {
	if s == nil {
		return CertificateState{}, errors.New("certificate store is not initialized")
	}
	hash = strings.ToLower(strings.TrimSpace(hash))
	if err := validateSHA256Hex("certificate hash", hash); err != nil {
		return CertificateState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.staged == nil || s.staged.hash != hash {
		return CertificateState{}, errors.New("cannot activate certificate before it is staged")
	}
	s.activeHash = s.staged.hash
	s.expiresAt = s.staged.expiresAt
	s.activeDER = cloneDERChain(s.staged.chainDER)
	accepted, err := normalizeHashes(append(s.accepted, s.activeHash))
	if err != nil {
		return CertificateState{}, err
	}
	s.accepted = accepted
	s.staged = nil
	return s.stateLocked(), nil
}

func (s *CertificateStore) PruneAcceptedToActive() (CertificateState, error) {
	if s == nil {
		return CertificateState{}, errors.New("certificate store is not initialized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accepted = []string{s.activeHash}
	return s.stateLocked(), nil
}

func (s *CertificateStore) ActiveTLSCertificate() (tls.Certificate, bool) {
	if s == nil {
		return tls.Certificate{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.activeDER) == 0 || s.material == nil || s.material.TLSPrivateKey == nil {
		return tls.Certificate{}, false
	}
	return tls.Certificate{
		Certificate: cloneDERChain(s.activeDER),
		PrivateKey:  s.material.TLSPrivateKey,
		Leaf:        nil,
	}, true
}

func (s *CertificateStore) stateLocked() CertificateState {
	return CertificateState{
		ActiveCertSHA256:   s.activeHash,
		AcceptedCertSHA256: append([]string(nil), s.accepted...),
		ExpiresAt:          s.expiresAt,
	}
}

func parseCertificateChain(input []byte) ([]*x509.Certificate, error) {
	if len(input) == 0 {
		return nil, errors.New("certificate chain is required")
	}
	rest := input
	var certs []*x509.Certificate
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate PEM block: %w", err)
			}
			certs = append(certs, cert)
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

func normalizeHashes(values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		if err := validateSHA256Hex("certificate hash", normalized); err != nil {
			return nil, err
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out, nil
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

func containsHash(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func validateSHA256Hex(name string, value string) error {
	if len(value) != 64 {
		return fmt.Errorf("%s must be 32-byte lowercase hex", name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%s must be hex: %w", name, err)
	}
	if value != strings.ToLower(value) {
		return fmt.Errorf("%s must be lowercase hex", name)
	}
	return nil
}

func cloneDERChain(chain [][]byte) [][]byte {
	out := make([][]byte, 0, len(chain))
	for _, cert := range chain {
		out = append(out, append([]byte(nil), cert...))
	}
	return out
}
