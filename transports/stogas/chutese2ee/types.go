package chutese2ee

import (
	"errors"
	"strconv"
	"time"
)

const (
	invocationPath             = "/e2e/invoke"
	discoveryPathPrefix        = "/e2e/instances/"
	evidencePathPrefix         = "/chutes/"
	measurementsPath           = "/servers/tee/measurements"
	ticketExpiryMargin         = 5 * time.Second
	attestationLifetime        = 3 * time.Minute
	instanceCooldown           = 5 * time.Second
	warmExpiryThreshold        = 15 * time.Second
	ticketWarmCheckInterval    = time.Second
	ticketDemandWindow         = 30 * time.Second
	ticketRefillRunway         = 5 * time.Second
	ticketRefillRetryMinimum   = time.Second
	ticketRefillRetryMaximum   = 30 * time.Second
	attestationRefreshInterval = 2 * time.Minute
	attestationRefreshJitter   = 15 * time.Second
	attestationRefreshTick     = 5 * time.Second
	attestationObservationTTL  = 3 * time.Minute
	attestationRetryMinimum    = 10 * time.Second
	attestationRetryMaximum    = 30 * time.Second
	transportTimeout           = 30 * time.Second
	attestationTimeout         = 55 * time.Second
	maxDiscoveryBody           = 2 << 20
	maxEvidenceBody            = 64 << 20
	maxMeasurementBody         = 4 << 20
	maxNRASBody                = 16 << 20
	maxDecryptedResponse       = 128 << 20
	maxEncryptedSSELine        = 8 << 20
	maximumDiscoveredInstances = 5
	maximumInvokeAttempts      = maximumDiscoveredInstances
)

var (
	ErrNoUsableTicket       = errors.New("no verified Chutes E2EE ticket is available")
	ErrAttestationFailed    = errors.New("Chutes TEE attestation failed")
	ErrInvalidE2EERequest   = errors.New("invalid Chutes E2EE request")
	ErrInvalidE2EEResponse  = errors.New("invalid Chutes E2EE response")
	ErrMeasurementPolicy    = errors.New("invalid Chutes TEE measurement policy")
	ErrGPUAttestationFailed = errors.New("NVIDIA GPU attestation failed")
)

type ModelTarget struct {
	ChuteID  string
	GPUCount int
}

type ModelResolver func(upstreamModel string) (target ModelTarget, ok bool)

func modelTargetKey(target ModelTarget) string {
	return target.ChuteID + "\x00" + strconv.Itoa(target.GPUCount)
}

type discoveredInstance struct {
	ID        string   `json:"instance_id"`
	PublicKey string   `json:"e2e_pubkey"`
	Tickets   []string `json:"nonces"`
}

type discoveryResponse struct {
	Instances     []discoveredInstance `json:"instances"`
	ExpiresIn     int                  `json:"nonce_expires_in"`
	ExpiresAtUnix int64                `json:"nonce_expires_at"`
}

type reservedTicket struct {
	ChuteID    string
	InstanceID string
	PublicKey  string
	Value      string
}

type verifiedInstance struct {
	InstanceID            string
	PublicKey             string
	GPUCount              int
	MeasurementDigest     string
	MeasurementName       string
	MeasurementVersion    string
	KeyPossessionVerified bool
	VerifiedAt            time.Time
	ValidUntil            time.Time
}

type instanceTickets struct {
	PublicKey string
	Values    []pooledTicket
}

type pooledTicket struct {
	Value     string
	ExpiresAt time.Time
}

type ticketPool struct {
	Instances map[string]*instanceTickets
	Order     []string
	Cursor    int
}

type ticketActivity struct {
	Target       ModelTarget
	LastDemandAt time.Time
	LastRefillAt time.Time
	Takes        []time.Time
}

type ticketRefillState struct {
	Failures  int
	LastError error
	NotBefore time.Time
}

type ticketRefillBackoffError struct {
	Cause      error
	RetryAfter time.Duration
}

func (e *ticketRefillBackoffError) Error() string {
	return "Chutes ticket discovery is temporarily backed off"
}

func (e *ticketRefillBackoffError) Unwrap() error {
	return e.Cause
}

type attestationResult struct {
	Instances       map[string]verifiedInstance
	FailureCounts   map[string]int
	PolicyDigest    string
	PolicyFetchedAt time.Time
	Attempted       bool
	Complete        bool
}

type instanceEvidence struct {
	Quote        string           `json:"quote"`
	GPUEvidence  []map[string]any `json:"gpu_evidence"`
	InstanceID   string           `json:"instance_id"`
	Certificate  string           `json:"certificate"`
	Signature    string           `json:"signature"`
	AttestedBody string           `json:"attested_body"`
}

type evidenceResponse struct {
	Evidence          []instanceEvidence `json:"evidence"`
	FailedInstanceIDs []string           `json:"failed_instance_ids"`
}

type measurementPolicy struct {
	Version      string            `json:"version"`
	Name         string            `json:"name"`
	MRTD         string            `json:"mrtd"`
	BootRTMRs    map[string]string `json:"boot_rtmrs"`
	RuntimeRTMRs map[string]string `json:"runtime_rtmrs"`
	ExpectedGPUs []string          `json:"expected_gpus"`
	GPUCount     int               `json:"gpu_count"`
}

type httpStatusError struct {
	Operation  string
	StatusCode int
	RetryAfter time.Duration
}

func (e *httpStatusError) Error() string {
	return e.Operation + " returned HTTP " + statusText(e.StatusCode)
}

func statusText(status int) string {
	if status < 100 || status > 999 {
		return "error"
	}
	return strconv.Itoa(status)
}
