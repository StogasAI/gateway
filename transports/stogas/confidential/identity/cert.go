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

const maxCertificateChainBytes = 256 * 1024
const maxCertificateChainLength = 16

type CertificateStore struct {
	mu                sync.RWMutex
	material          *Material
	verificationRoots *x509.CertPool
	activeHash        string
	accepted          []string
	expiresAt         time.Time
	activeDER         [][]byte
	staged            *stagedCertificate
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

type CertificateChainInput struct {
	ChainPEM       []byte
	DNSNames       []string
	ExpectedSHA256 string
}

type stagedCertificate struct {
	hash      string
	chainDER  [][]byte
	expiresAt time.Time
}

func NewCertificateStore(material *Material, activeHash string, accepted []string, expiresAt time.Time, verificationRoots *x509.CertPool) (*CertificateStore, error) {
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
	if len(accepted) > 2 {
		return nil, errors.New("certificate store cannot accept more than two certificate hashes")
	}
	if verificationRoots != nil {
		verificationRoots = verificationRoots.Clone()
	}
	return &CertificateStore{
		material:          material,
		verificationRoots: verificationRoots,
		activeHash:        activeHash,
		accepted:          accepted,
		expiresAt:         expiresAt.UTC(),
	}, nil
}

func NewProvisionalCertificateStore(material *Material, now time.Time, verificationRoots *x509.CertPool) (*CertificateStore, error) {
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
	if verificationRoots != nil {
		verificationRoots = verificationRoots.Clone()
	}
	return &CertificateStore{
		material:          material,
		verificationRoots: verificationRoots,
		activeHash:        hash,
		accepted:          nil,
		expiresAt:         notAfter,
		activeDER:         [][]byte{append([]byte(nil), der...)},
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

func (s *CertificateStore) StageRenewedChain(input CertificateChainInput) (CertificateState, error) {
	if s == nil || s.material == nil {
		return CertificateState{}, errors.New("certificate store is not initialized")
	}
	verified, err := s.verifyRenewedChain(input)
	if err != nil {
		return CertificateState{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if verified.hash == s.activeHash {
		return CertificateState{}, errors.New("renewed certificate hash must differ from active certificate hash")
	}
	if s.staged != nil {
		if s.staged.hash == verified.hash {
			return s.stateLocked(), nil
		}
		return CertificateState{}, errors.New("cannot replace an unrelated staged certificate")
	}
	if len(s.accepted) >= 2 {
		return CertificateState{}, errors.New("certificate store already accepts two certificate hashes")
	}
	accepted, err := normalizeHashes(append(s.accepted, verified.hash))
	if err != nil {
		return CertificateState{}, err
	}
	if len(accepted) > 2 {
		return CertificateState{}, errors.New("certificate store cannot accept more than two certificate hashes")
	}
	expectedHash := strings.ToLower(strings.TrimSpace(input.ExpectedSHA256))
	staged := &stagedCertificate{
		hash:      verified.hash,
		chainDER:  cloneDERChain(verified.chainDER),
		expiresAt: verified.expiresAt,
	}
	if !containsHash(accepted, expectedHash) || staged.hash != expectedHash {
		return CertificateState{}, errors.New("staged certificate state did not match expected hash")
	}
	s.staged = staged
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
	staged := s.staged
	accepted, err := normalizeHashes(append(s.accepted, hash))
	if err != nil {
		return CertificateState{}, err
	}
	if staged.hash != hash || !containsHash(accepted, hash) {
		return CertificateState{}, errors.New("active certificate state did not match expected hash")
	}
	s.activeHash = hash
	s.accepted = accepted
	s.expiresAt = staged.expiresAt
	s.activeDER = cloneDERChain(staged.chainDER)
	s.staged = nil
	return s.stateLocked(), nil
}

func (s *CertificateStore) InstallActiveChain(input CertificateChainInput) (CertificateState, error) {
	if s == nil || s.material == nil {
		return CertificateState{}, errors.New("certificate store is not initialized")
	}
	verified, err := s.verifyRenewedChain(input)
	if err != nil {
		return CertificateState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if verified.hash == s.activeHash {
		return CertificateState{}, errors.New("renewed certificate hash must differ from active certificate hash")
	}
	if s.staged != nil {
		if s.staged.hash != verified.hash {
			return CertificateState{}, errors.New("cannot replace an unrelated staged certificate")
		}
	} else if len(s.accepted) >= 2 {
		return CertificateState{}, errors.New("certificate store already accepts two certificate hashes")
	}
	expectedHash := strings.ToLower(strings.TrimSpace(input.ExpectedSHA256))
	nextAccepted := []string{verified.hash}
	if verified.hash != expectedHash || nextAccepted[0] != expectedHash {
		return CertificateState{}, errors.New("installed certificate state did not match expected hash")
	}
	s.activeHash = expectedHash
	s.accepted = nextAccepted
	s.expiresAt = verified.expiresAt
	s.activeDER = cloneDERChain(verified.chainDER)
	s.staged = nil
	return s.stateLocked(), nil
}

func (s *CertificateStore) PruneAcceptedToActive(expectedHash string) (CertificateState, error) {
	if s == nil {
		return CertificateState{}, errors.New("certificate store is not initialized")
	}
	expectedHash = strings.ToLower(strings.TrimSpace(expectedHash))
	if err := validateSHA256Hex("expected active certificate hash", expectedHash); err != nil {
		return CertificateState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeHash != expectedHash {
		return CertificateState{}, errors.New("cannot prune a non-active certificate hash")
	}
	s.accepted = []string{expectedHash}
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

type verifiedCertificateChain struct {
	chainDER  [][]byte
	expiresAt time.Time
	hash      string
}

func (s *CertificateStore) verifyRenewedChain(input CertificateChainInput) (verifiedCertificateChain, error) {
	expectedHash := strings.ToLower(strings.TrimSpace(input.ExpectedSHA256))
	if err := validateSHA256Hex("expected certificate hash", expectedHash); err != nil {
		return verifiedCertificateChain{}, err
	}
	dnsNames := normalizeNames(input.DNSNames)
	if len(dnsNames) == 0 {
		return verifiedCertificateChain{}, errors.New("renewed certificate requires an expected DNS name")
	}
	certs, err := parseCertificateChain(input.ChainPEM)
	if err != nil {
		return verifiedCertificateChain{}, err
	}
	leaf := certs[0]
	if leaf.IsCA {
		return verifiedCertificateChain{}, errors.New("renewed server certificate cannot be a CA certificate")
	}
	hash := CertSHA256Hex(leaf.Raw)
	if hash != expectedHash {
		return verifiedCertificateChain{}, errors.New("renewed certificate hash did not match expected hash")
	}
	spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return verifiedCertificateChain{}, fmt.Errorf("marshal renewed certificate spki: %w", err)
	}
	if SHA256Hex(spki) != s.material.TLSSPKISHA256 {
		return verifiedCertificateChain{}, errors.New("renewed certificate must reuse the existing TLS public key")
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	roots := s.verificationRoots
	if roots == nil {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return verifiedCertificateChain{}, fmt.Errorf("load system certificate roots: %w", err)
		}
	}
	for _, dnsName := range dnsNames {
		if _, err := leaf.Verify(x509.VerifyOptions{
			DNSName:       dnsName,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			Roots:         roots,
		}); err != nil {
			return verifiedCertificateChain{}, fmt.Errorf("verify renewed certificate for %s: %w", dnsName, err)
		}
	}
	chainDER := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		chainDER = append(chainDER, append([]byte(nil), cert.Raw...))
	}
	return verifiedCertificateChain{
		chainDER:  chainDER,
		expiresAt: leaf.NotAfter.UTC(),
		hash:      hash,
	}, nil
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
