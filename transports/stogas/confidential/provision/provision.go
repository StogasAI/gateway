package provision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/confidential/quote"
)

const (
	DefaultMaxResponseBytes = 1 << 20
	SecretReleaseSchemaV1   = "stogas.confidential-secret-release.v1"
)

type Client struct {
	BaseURL            string
	AccessClientID     string
	AccessClientSecret string
	HTTPClient         *http.Client
	MaxResponseBytes   int64
	AllowInsecureLocal bool
}

type HeartbeatInput struct {
	CertExpiresAt time.Time
	Health        NodeHealth
	NodeID        string
	ObservedAt    time.Time
	Quote         *quote.Snapshot
	SigningKey    ed25519.PrivateKey
}

type NodeHealth struct {
	LastQuoteError string            `json:"last_quote_error,omitempty"`
	Ready          bool              `json:"ready"`
	SecretVersions map[string]string `json:"secret_versions"`
}

type HeartbeatResponse struct {
	CertificateInstruction *CertificateInstruction `json:"certificate_instruction"`
	NodeID                 string                  `json:"node_id"`
	OK                     bool                    `json:"ok"`
	Ready                  bool                    `json:"ready"`
	ReadyUntil             *time.Time              `json:"ready_until"`
	Secrets                *SecretBundle           `json:"secrets"`
	Shutdown               bool                    `json:"shutdown"`
}

type CertificateInstruction struct {
	Action           string
	ActiveCertSHA256 string
	CertChainPEM     string
	CertSHA256       string
	CommonName       string
	DNSNames         []string
	NewCertSHA256    string
	OrderID          string
}

type CertificateCSRSubmission struct {
	CSRDER     []byte
	NodeID     string
	OrderID    string
	SigningKey ed25519.PrivateKey
}

type CertificateCSRSubmissionResponse struct {
	NodeID  string `json:"node_id"`
	OK      bool   `json:"ok"`
	OrderID string `json:"order_id"`
}

type SecretBundle struct {
	NodeID           string             `json:"node_id"`
	ReportDataSHA512 string             `json:"report_data_sha512"`
	Schema           string             `json:"schema"`
	Secrets          []SecretCiphertext `json:"secrets"`
}

type SecretCiphertext struct {
	AADSHA256       string `json:"aad_sha256"`
	Ciphertext      string `json:"ciphertext"`
	EncapsulatedKey string `json:"encapsulated_key"`
	KeyID           string `json:"key_id"`
	Name            string `json:"name"`
	Version         string `json:"version"`
}

type controlError struct {
	Message string `json:"message"`
	Reason  string `json:"reason,omitempty"`
}

type HTTPResponseError struct {
	Message    string
	Path       string
	Reason     string
	StatusCode int
}

func (e *HTTPResponseError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("control %s rejected request: %s: %s", e.Path, e.Message, e.Reason)
	}
	if e.Message != "" {
		return fmt.Sprintf("control %s rejected request: %s", e.Path, e.Message)
	}
	return fmt.Sprintf("control %s rejected request with status %d", e.Path, e.StatusCode)
}

// IsAuthoritativeRejection distinguishes a definitive Control policy/validation response from
// transport failures and explicitly retryable HTTP responses. Only definitive responses may
// revoke a still-valid admission lease immediately.
func IsAuthoritativeRejection(err error) bool {
	var responseError *HTTPResponseError
	if !errors.As(err, &responseError) {
		return false
	}
	if responseError.StatusCode < 400 || responseError.StatusCode >= 500 {
		return false
	}
	switch responseError.StatusCode {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return false
	default:
		return true
	}
}

func (c Client) SendHeartbeat(ctx context.Context, input HeartbeatInput) (*HeartbeatResponse, error) {
	if input.Quote == nil {
		return nil, errors.New("heartbeat quote snapshot is required")
	}
	if input.NodeID == "" {
		return nil, errors.New("heartbeat node id is required")
	}
	if input.CertExpiresAt.IsZero() {
		return nil, errors.New("heartbeat cert expiry is required")
	}
	if input.ObservedAt.IsZero() {
		input.ObservedAt = time.Now().UTC()
	}
	signature, err := signHeartbeat(input)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"cert_expires_at":    formatTime(input.CertExpiresAt),
		"health":             input.Health,
		"node_id":            input.NodeID,
		"observed_at":        formatTime(input.ObservedAt),
		"quote":              base64.RawURLEncoding.EncodeToString(input.Quote.Quote),
		"quote_generated_at": formatTime(input.Quote.GeneratedAt),
		"report_data":        input.Quote.Payload,
		"report_data_sha512": strings.ToLower(input.Quote.ReportDataHex),
		"signature":          signature,
	}
	var response heartbeatResponseJSON
	if err := c.postJSON(ctx, "/api/fleet/heartbeat", body, &response); err != nil {
		return nil, err
	}
	return parseHeartbeatResponse(response, input)
}

func (c Client) SubmitCertificateCSR(ctx context.Context, input CertificateCSRSubmission) (*CertificateCSRSubmissionResponse, error) {
	if input.NodeID == "" {
		return nil, errors.New("certificate CSR node ID is required")
	}
	if input.OrderID == "" {
		return nil, errors.New("certificate CSR order id is required")
	}
	if len(input.CSRDER) == 0 {
		return nil, errors.New("certificate CSR DER is required")
	}
	signature, err := signCertificateCSRSubmission(input)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"csr_der":   base64.RawURLEncoding.EncodeToString(input.CSRDER),
		"node_id":   strings.ToLower(input.NodeID),
		"order_id":  input.OrderID,
		"signature": signature,
	}

	var response certificateCSRSubmissionResponseJSON
	if err := c.postJSON(ctx, "/api/fleet/cert/csr", body, &response); err != nil {
		return nil, err
	}
	if !response.OK {
		return nil, errors.New("control certificate CSR response did not confirm ok")
	}
	if response.NodeID != strings.ToLower(input.NodeID) {
		return nil, errors.New("control certificate CSR response node ID mismatch")
	}
	if response.OrderID != input.OrderID {
		return nil, errors.New("control certificate CSR response order id mismatch")
	}
	return &CertificateCSRSubmissionResponse{
		NodeID:  response.NodeID,
		OK:      response.OK,
		OrderID: response.OrderID,
	}, nil
}

func (c Client) postJSON(ctx context.Context, path string, body any, out any) error {
	endpoint, err := c.endpoint(path)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	if strings.TrimSpace(c.AccessClientID) != "" || strings.TrimSpace(c.AccessClientSecret) != "" {
		req.Header.Set("CF-Access-Client-Id", strings.TrimSpace(c.AccessClientID))
		req.Header.Set("CF-Access-Client-Secret", strings.TrimSpace(c.AccessClientSecret))
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	limit := c.MaxResponseBytes
	if limit <= 0 {
		limit = DefaultMaxResponseBytes
	}
	bytes, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(bytes)) > limit {
		return fmt.Errorf("control response exceeded %d bytes", limit)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		controlErr := parseControlError(bytes)
		return &HTTPResponseError{
			Message:    controlErr.Message,
			Path:       path,
			Reason:     controlErr.Reason,
			StatusCode: resp.StatusCode,
		}
	}
	decoder := json.NewDecoder(bytesReader(bytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("decode control %s response: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("decode control %s response: trailing data", path)
	}
	return nil
}

func (c Client) endpoint(path string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(c.BaseURL))
	if err != nil {
		return "", fmt.Errorf("parse control url: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return "", errors.New("control url must be absolute")
	}
	if base.Scheme != "https" && !(c.AllowInsecureLocal && base.Scheme == "http" && isLocalHost(base.Hostname())) {
		return "", errors.New("control url must use https")
	}
	joined := base.ResolveReference(&url.URL{Path: path})
	return joined.String(), nil
}

type heartbeatResponseJSON struct {
	CertificateInstruction *certificateInstructionJSON `json:"certificate_instruction"`
	NodeID                 string                      `json:"node_id"`
	OK                     bool                        `json:"ok"`
	Ready                  bool                        `json:"ready"`
	ReadyUntil             *string                     `json:"ready_until"`
	Secrets                *secretBundleJSON           `json:"secrets"`
	Shutdown               bool                        `json:"shutdown"`
}

type certificateInstructionJSON struct {
	Action           string   `json:"action"`
	ActiveCertSHA256 string   `json:"active_cert_sha256,omitempty"`
	CertChainPEM     string   `json:"cert_chain_pem,omitempty"`
	CertSHA256       string   `json:"cert_sha256,omitempty"`
	CommonName       string   `json:"common_name,omitempty"`
	DNSNames         []string `json:"dns_names,omitempty"`
	NewCertSHA256    string   `json:"new_cert_sha256,omitempty"`
	OrderID          string   `json:"order_id"`
}

type certificateCSRSubmissionResponseJSON struct {
	NodeID  string `json:"node_id"`
	OK      bool   `json:"ok"`
	OrderID string `json:"order_id"`
}

type secretBundleJSON struct {
	NodeID           string             `json:"node_id"`
	ReportDataSHA512 string             `json:"report_data_sha512"`
	Schema           string             `json:"schema"`
	Secrets          []SecretCiphertext `json:"secrets"`
}

func parseHeartbeatResponse(response heartbeatResponseJSON, request HeartbeatInput) (*HeartbeatResponse, error) {
	if !response.OK {
		return nil, errors.New("control heartbeat response did not confirm ok")
	}
	if response.NodeID == "" {
		return nil, errors.New("control heartbeat response missing node ID")
	}
	var readyUntil *time.Time
	if response.ReadyUntil != nil {
		parsed, err := parseTime("ready_until", *response.ReadyUntil)
		if err != nil {
			return nil, err
		}
		readyUntil = &parsed
	}
	if response.Ready != (readyUntil != nil) {
		return nil, errors.New("control heartbeat readiness lease is inconsistent")
	}
	certificateInstruction, err := parseCertificateInstruction(response.CertificateInstruction)
	if err != nil {
		return nil, err
	}
	secrets, err := parseSecretBundle(response.Secrets, response.NodeID, request.Quote.ReportDataHex)
	if err != nil {
		return nil, err
	}
	return &HeartbeatResponse{
		CertificateInstruction: certificateInstruction,
		NodeID:                 response.NodeID,
		OK:                     response.OK,
		Ready:                  response.Ready,
		ReadyUntil:             readyUntil,
		Secrets:                secrets,
		Shutdown:               response.Shutdown,
	}, nil
}

func parseCertificateInstruction(input *certificateInstructionJSON) (*CertificateInstruction, error) {
	if input == nil {
		return nil, nil
	}
	if strings.TrimSpace(input.OrderID) == "" {
		return nil, errors.New("control certificate instruction missing order id")
	}
	instruction := &CertificateInstruction{
		Action:           input.Action,
		ActiveCertSHA256: strings.ToLower(input.ActiveCertSHA256),
		CertChainPEM:     input.CertChainPEM,
		CertSHA256:       strings.ToLower(input.CertSHA256),
		CommonName:       strings.TrimSpace(input.CommonName),
		DNSNames:         normalizeStringSet(input.DNSNames),
		NewCertSHA256:    strings.ToLower(input.NewCertSHA256),
		OrderID:          strings.TrimSpace(input.OrderID),
	}
	switch instruction.Action {
	case "request_csr":
		if len(instruction.DNSNames) == 0 {
			return nil, errors.New("control certificate CSR instruction missing DNS names")
		}
	case "install_renewed_chain", "install_active_chain":
		if strings.TrimSpace(instruction.CertChainPEM) == "" {
			return nil, errors.New("control certificate install instruction missing certificate chain")
		}
		if !isLowerHash(instruction.NewCertSHA256) {
			return nil, errors.New("control certificate install instruction has invalid new certificate hash")
		}
	case "activate_staged":
		if !isLowerHash(instruction.CertSHA256) {
			return nil, errors.New("control certificate activate instruction has invalid certificate hash")
		}
	case "prune_accepted":
		if !isLowerHash(instruction.ActiveCertSHA256) {
			return nil, errors.New("control certificate prune instruction has invalid active certificate hash")
		}
	default:
		return nil, fmt.Errorf("unsupported control certificate instruction %q", instruction.Action)
	}
	return instruction, nil
}

func parseSecretBundle(response *secretBundleJSON, nodeID, reportDataSHA512 string) (*SecretBundle, error) {
	if response == nil {
		return nil, nil
	}
	if response.Schema != SecretReleaseSchemaV1 {
		return nil, fmt.Errorf("unsupported secret release schema %q", response.Schema)
	}
	if response.NodeID != strings.ToLower(nodeID) {
		return nil, errors.New("secret release node ID mismatch")
	}
	if response.ReportDataSHA512 != strings.ToLower(reportDataSHA512) {
		return nil, errors.New("secret release report-data hash mismatch")
	}
	if len(response.Secrets) == 0 {
		return nil, errors.New("secret release response contains no secrets")
	}
	for _, secret := range response.Secrets {
		if err := secret.Validate(); err != nil {
			return nil, err
		}
	}
	return &SecretBundle{
		NodeID:           response.NodeID,
		ReportDataSHA512: response.ReportDataSHA512,
		Schema:           response.Schema,
		Secrets:          append([]SecretCiphertext(nil), response.Secrets...),
	}, nil
}

func (s SecretCiphertext) Validate() error {
	for name, value := range map[string]string{
		"aad_sha256":       s.AADSHA256,
		"ciphertext":       s.Ciphertext,
		"encapsulated_key": s.EncapsulatedKey,
		"key_id":           s.KeyID,
		"name":             s.Name,
		"version":          s.Version,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("secret ciphertext missing %s", name)
		}
	}
	if !isBase64URL(s.Ciphertext) || !isBase64URL(s.EncapsulatedKey) {
		return errors.New("secret ciphertext fields must be base64url")
	}
	return nil
}

func parseControlError(bytes []byte) controlError {
	var response controlError
	if err := json.Unmarshal(bytes, &response); err != nil {
		return controlError{}
	}
	return response
}

func parseTime(name string, value string) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, fmt.Errorf("control response missing %s", name)
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse control response %s: %w", name, err)
	}
	return parsed.UTC(), nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func isLocalHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasSuffix(host, ".localhost")
}

func isBase64URL(value string) bool {
	if value == "" {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil
}

func isLowerHash(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func normalizeStringSet(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
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
	return out
}

func bytesReader(data []byte) *bytes.Reader {
	return bytes.NewReader(data)
}
