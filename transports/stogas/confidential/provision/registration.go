package provision

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	verifier "github.com/StogasAI/verifier/go"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
)

const registrationAttemptTimeout = 30 * time.Second

type RegistrationChallenge struct {
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Boot is the exact logged boot document, sent as its JSON object.
type BootRegistration struct {
	InstanceID string          `json:"instance_id"`
	Boot       json.RawMessage `json:"boot"`
	CSRDER     string          `json:"csr_der"`
}

// Provisioning is Control's sealed envelope; the node keys check its binding when opening it.
type RegistrationResponse struct {
	Status       string          `json:"status"`
	NodeID       string          `json:"node_id"`
	Inclusion    json.RawMessage `json:"inclusion,omitempty"`
	Provisioning json.RawMessage `json:"provisioning,omitempty"`
}

type BootCertificateResponse struct {
	Status         string `json:"status"`
	NodeID         string `json:"node_id"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
}

type bootRequest struct {
	NodeID     string          `json:"node_id"`
	IssuedAtMS int64           `json:"issued_at_ms"`
	Signature  string          `json:"signature"`
	Boot       json.RawMessage `json:"boot"`
	Inclusion  json.RawMessage `json:"inclusion"`
}

// The node ID comes from this boot's own verified identity.
func newBootRequest(nodeID string, boot attest.BootEvidence, keys *verifier.NodeKeys, purpose verifier.BootRequestPurpose) (bootRequest, error) {
	if keys == nil || nodeID == "" {
		return bootRequest{}, errors.New("boot request requires the node identity and key")
	}
	issued := time.Now()
	signature, err := keys.SignBootRequest(purpose, nodeID, issued)
	if err != nil {
		return bootRequest{}, errors.New("boot request signing failed")
	}
	return bootRequest{nodeID, issued.UnixMilli(), base64.RawURLEncoding.EncodeToString(signature), boot.Document, boot.Inclusion}, nil
}

// CompleteBootRegistration acknowledges locally verified installation. Exact retries
// let the authority discard its temporary recovery payload without another secret release.
func (c Client) CompleteBootRegistration(ctx context.Context, nodeID string, boot attest.BootEvidence, keys *verifier.NodeKeys) error {
	request, err := newBootRequest(nodeID, boot, keys, verifier.BootRegistrationComplete)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, registrationAttemptTimeout)
	defer cancel()
	var response struct {
		Status string `json:"status"`
		NodeID string `json:"node_id"`
	}
	if err := c.registrationClient().postJSON(ctx, "/api/fleet/registration/complete", request, &response); err != nil {
		return err
	}
	if response.Status != "complete" || response.NodeID != nodeID {
		return errors.New("invalid registration acknowledgement")
	}
	return nil
}

// RenewBootCertificate carries the exact logged boot and a CSR for its existing TLS key.
// The caller checks the returned chain, hostname, validity and key before installation.
func (c Client) RenewBootCertificate(ctx context.Context, nodeID string, boot attest.BootEvidence, csrDER []byte, keys *verifier.NodeKeys) (*BootCertificateResponse, error) {
	authorization, err := newBootRequest(nodeID, boot, keys, verifier.BootCertificateRenewal)
	if err != nil {
		return nil, err
	}
	request := struct {
		bootRequest
		CSRDER string `json:"csr_der"`
	}{authorization, base64.RawURLEncoding.EncodeToString(csrDER)}
	ctx, cancel := context.WithTimeout(ctx, registrationAttemptTimeout)
	defer cancel()
	c = c.registrationClient()
	if c.MaxResponseBytes > 40*1024 {
		c.MaxResponseBytes = 40 * 1024
	}
	var response BootCertificateResponse
	if err := c.postJSON(ctx, "/api/fleet/registration/certificate", request, &response); err != nil {
		return nil, err
	}
	if response.NodeID != nodeID {
		return nil, errors.New("certificate returned another node")
	}
	switch response.Status {
	case "pending":
		if response.CertificatePEM != "" {
			return nil, errors.New("pending certificate included completion material")
		}
	case "ready":
		if response.CertificatePEM == "" || len(response.CertificatePEM) > 32*1024 {
			return nil, errors.New("invalid certificate completion")
		}
	default:
		return nil, errors.New("invalid certificate status")
	}
	return &response, nil
}

func (c Client) RegistrationChallenge(ctx context.Context, instanceID string) (*RegistrationChallenge, error) {
	if !instanceUUID(instanceID) {
		return nil, errors.New("invalid registration instance")
	}
	ctx, cancel := context.WithTimeout(ctx, registrationAttemptTimeout)
	defer cancel()
	c = c.registrationClient()
	var response RegistrationChallenge
	if err := c.postJSON(ctx, "/api/fleet/registration/challenge", map[string]string{"instance_id": instanceID}, &response); err != nil {
		return nil, err
	}
	if !isLowerHash(response.Challenge) || !response.ExpiresAt.After(time.Now()) {
		return nil, errors.New("invalid or expired registration challenge")
	}
	return &response, nil
}

// RegisterBoot sends the locally appraised boot unchanged on every retry. Ready
// still requires offline verification of inclusion and the decrypted certificate
// before the runtime can open public admission. No provider credentials are sent.
func (c Client) RegisterBoot(ctx context.Context, request BootRegistration, expectedNodeID string) (*RegistrationResponse, error) {
	if !instanceUUID(request.InstanceID) || expectedNodeID == "" || !json.Valid(request.Boot) {
		return nil, errors.New("invalid registration identity")
	}
	if csr, err := base64.RawURLEncoding.Strict().DecodeString(request.CSRDER); err != nil || len(csr) == 0 || len(csr) > 16*1024 {
		return nil, errors.New("invalid registration CSR encoding")
	}
	ctx, cancel := context.WithTimeout(ctx, registrationAttemptTimeout)
	defer cancel()
	c = c.registrationClient()
	var response RegistrationResponse
	if err := c.postJSON(ctx, "/api/fleet/registration", request, &response); err != nil {
		return nil, err
	}
	if response.NodeID != expectedNodeID {
		return nil, errors.New("registration returned another node")
	}
	switch response.Status {
	case "pending":
		if response.Provisioning != nil || len(response.Inclusion) != 0 {
			return nil, errors.New("pending registration included completion material")
		}
	case "ready":
		if absentJSON(response.Provisioning) || absentJSON(response.Inclusion) {
			return nil, errors.New("registration omitted its boot-bound completion")
		}
	default:
		return nil, errors.New("invalid registration status")
	}
	return &response, nil
}

func (c Client) registrationClient() Client {
	// At most 60 KiB of boot/proof and 88 KiB of encoded provisioning plus framing.
	if c.MaxResponseBytes <= 0 || c.MaxResponseBytes > 160*1024 {
		c.MaxResponseBytes = 160 * 1024
	}
	return c
}

func instanceUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

// Keep canonical binary encoding at the call site without exposing the TLS key.
func NewBootRegistration(instanceID string, document, csrDER []byte) BootRegistration {
	return BootRegistration{InstanceID: instanceID, Boot: document, CSRDER: base64.RawURLEncoding.EncodeToString(csrDER)}
}

func absentJSON(value json.RawMessage) bool {
	return len(value) == 0 || string(value) == "null"
}
