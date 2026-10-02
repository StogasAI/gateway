package provision

import (
	"context"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
)

const registrationAttemptTimeout = 30 * time.Second

type RegistrationChallenge struct {
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

type BootRegistration struct {
	InstanceID string            `json:"instance_id"`
	Boot       attest.BootRecord `json:"boot"`
	CSRDER     string            `json:"csr_der"`
}

type RegistrationResponse struct {
	Status       string            `json:"status"`
	NodeID       string            `json:"node_id"`
	Inclusion    json.RawMessage   `json:"inclusion,omitempty"`
	Provisioning *BootProvisioning `json:"provisioning,omitempty"`
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

const certificateRequestDomain = "stogas.certificate-renewal.v1\x00"
const completionRequestDomain = "stogas.registration-complete.v1\x00"

func newBootRequest(nodeID string, boot attest.BootEvidence, signingKey *mldsa.PrivateKey, domain string) (bootRequest, error) {
	_, suffix, found := strings.Cut(nodeID, "-")
	_, suffix, foundSecond := strings.Cut(suffix, "-")
	bytes, err := hex.DecodeString(suffix)
	if !found || !foundSecond || err != nil || len(bytes) != 32 || attest.SNPNodeID([32]byte(bytes)) != nodeID {
		return bootRequest{}, errors.New("invalid boot request node identity")
	}
	if signingKey == nil || signingKey.PublicKey().Parameters() != mldsa.MLDSA65() {
		return bootRequest{}, errors.New("boot request requires the node signing key")
	}
	issued := time.Now().UnixMilli()
	signature, err := signingKey.Sign(nil, bootRequestTranscript(domain, nodeID, issued), &mldsa.Options{})
	if err != nil {
		return bootRequest{}, errors.New("boot request signing failed")
	}
	return bootRequest{nodeID, issued, base64.RawURLEncoding.EncodeToString(signature), boot.Document, boot.Inclusion}, nil
}

func bootRequestTranscript(domain, nodeID string, issued int64) []byte {
	message := append([]byte(domain), []byte(nodeID)...)
	message = append(message, 0)
	return binary.BigEndian.AppendUint64(message, uint64(issued))
}

// CompleteBootRegistration acknowledges locally verified installation. Exact retries
// let the authority discard its temporary recovery payload without another secret release.
func (c Client) CompleteBootRegistration(ctx context.Context, nodeID string, boot attest.BootEvidence, signingKey *mldsa.PrivateKey) error {
	request, err := newBootRequest(nodeID, boot, signingKey, completionRequestDomain)
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
func (c Client) RenewBootCertificate(ctx context.Context, nodeID string, boot attest.BootEvidence, csrDER []byte, signingKey *mldsa.PrivateKey) (*BootCertificateResponse, error) {
	authorization, err := newBootRequest(nodeID, boot, signingKey, certificateRequestDomain)
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
	if !instanceUUID(request.InstanceID) || expectedNodeID == "" {
		return nil, errors.New("invalid registration identity")
	}
	digest, err := request.Boot.Digest()
	if err != nil {
		return nil, err
	}
	if _, err := decodeBootCiphertext(request.CSRDER, 1, 16*1024); err != nil {
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
		if response.Provisioning == nil || len(response.Inclusion) == 0 || string(response.Inclusion) == "null" ||
			response.Provisioning.Schema != BootProvisioningSchema || response.Provisioning.BootSHA256 != hex.EncodeToString(digest[:]) {
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
func NewBootRegistration(instanceID string, boot attest.BootRecord, csrDER []byte) BootRegistration {
	return BootRegistration{InstanceID: instanceID, Boot: boot, CSRDER: base64.RawURLEncoding.EncodeToString(csrDER)}
}
