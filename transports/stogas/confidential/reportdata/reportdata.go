package reportdata

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	SchemaV1             = "stogas.node-report.v1"
	DrandNetworkQuicknet = "quicknet"
	QuicknetChainHash    = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
)

type Drand struct {
	Network    string `json:"network"`
	ChainHash  string `json:"chain_hash"`
	Round      uint64 `json:"round"`
	Randomness string `json:"randomness"`
	Signature  string `json:"signature"`
}

type Payload struct {
	Schema             string   `json:"schema"`
	ReleaseMeasurement string   `json:"release_measurement"`
	Region             string   `json:"region"`
	CatalogHash        string   `json:"catalog_hash"`
	TLSSPKISHA256      string   `json:"tls_spki_sha256"`
	ActiveCertSHA256   string   `json:"active_cert_sha256"`
	AcceptedCertSHA256 []string `json:"accepted_cert_sha256"`
	HPKEPublicKey      string   `json:"hpke_public_key"`
	Ed25519PublicKey   string   `json:"ed25519_public_key"`
	Drand              Drand    `json:"drand"`
}

func NewPayload(input Payload) (Payload, error) {
	payload := input
	if payload.Schema == "" {
		payload.Schema = SchemaV1
	}
	if payload.Drand.Network == "" {
		payload.Drand.Network = DrandNetworkQuicknet
	}
	if payload.Drand.ChainHash == "" {
		payload.Drand.ChainHash = QuicknetChainHash
	}
	payload.AcceptedCertSHA256 = append([]string(nil), payload.AcceptedCertSHA256...)
	sort.Strings(payload.AcceptedCertSHA256)
	if err := payload.Validate(); err != nil {
		return Payload{}, err
	}
	return payload, nil
}

func (p Payload) Validate() error {
	if p.Schema != SchemaV1 {
		return fmt.Errorf("unsupported report data schema %q", p.Schema)
	}
	for name, value := range map[string]string{
		"release_measurement": p.ReleaseMeasurement,
		"region":              p.Region,
		"catalog_hash":        p.CatalogHash,
		"tls_spki_sha256":     p.TLSSPKISHA256,
		"active_cert_sha256":  p.ActiveCertSHA256,
		"hpke_public_key":     p.HPKEPublicKey,
		"ed25519_public_key":  p.Ed25519PublicKey,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if len(p.AcceptedCertSHA256) == 0 {
		return errors.New("accepted_cert_sha256 is required")
	}
	if !contains(p.AcceptedCertSHA256, p.ActiveCertSHA256) {
		return errors.New("active_cert_sha256 must be included in accepted_cert_sha256")
	}
	for _, value := range []struct {
		name string
		hex  string
	}{
		{"release_measurement", p.ReleaseMeasurement},
		{"catalog_hash", p.CatalogHash},
		{"tls_spki_sha256", p.TLSSPKISHA256},
		{"active_cert_sha256", p.ActiveCertSHA256},
		{"drand.chain_hash", p.Drand.ChainHash},
		{"drand.randomness", p.Drand.Randomness},
		{"drand.signature", p.Drand.Signature},
	} {
		if err := validateHex(value.name, value.hex); err != nil {
			return err
		}
	}
	for _, certHash := range p.AcceptedCertSHA256 {
		if err := validateHex("accepted_cert_sha256", certHash); err != nil {
			return err
		}
	}
	if _, err := base64.RawURLEncoding.DecodeString(p.HPKEPublicKey); err != nil {
		return fmt.Errorf("hpke_public_key must be base64url: %w", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(p.Ed25519PublicKey); err != nil {
		return fmt.Errorf("ed25519_public_key must be base64url: %w", err)
	}
	if p.Drand.Network != DrandNetworkQuicknet {
		return fmt.Errorf("unsupported drand network %q", p.Drand.Network)
	}
	if p.Drand.ChainHash != QuicknetChainHash {
		return errors.New("unexpected drand quicknet chain hash")
	}
	if p.Drand.Round == 0 {
		return errors.New("drand round is required")
	}
	return nil
}

func CanonicalJSON(p Payload) ([]byte, error) {
	payload, err := NewPayload(p)
	if err != nil {
		return nil, err
	}
	return json.Marshal(payload)
}

func Hash(p Payload) ([64]byte, error) {
	canonical, err := CanonicalJSON(p)
	if err != nil {
		return [64]byte{}, err
	}
	return sha512.Sum512(canonical), nil
}

func HashHex(p Payload) (string, error) {
	sum, err := Hash(p)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum[:]), nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func validateHex(name string, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%s must be hex: %w", name, err)
	}
	return nil
}
