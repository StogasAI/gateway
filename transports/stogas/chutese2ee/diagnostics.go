package chutese2ee

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type OperationDiagnostic struct {
	At        time.Time `json:"at,omitzero"`
	Status    int       `json:"status,omitempty"`
	LatencyMS int64     `json:"latencyMs,omitempty"`
	Error     string    `json:"error,omitempty"`
}

type ChuteDiagnostic struct {
	ChuteID                        string              `json:"chuteId"`
	UpstreamModels                 []string            `json:"upstreamModels"`
	CredentialPools                int                 `json:"credentialPools"`
	CredentialPoolsInRefillBackoff int                 `json:"credentialPoolsInRefillBackoff"`
	VerifiedInstances              int                 `json:"verifiedInstances"`
	KeyPossessionVerifiedInstances int                 `json:"keyPossessionVerifiedInstances"`
	UsableTickets                  int                 `json:"usableTickets"`
	CooldownInstances              int                 `json:"cooldownInstances"`
	RefillBackoffSeconds           int64               `json:"refillBackoffSeconds,omitempty"`
	NearestTicketExpirySeconds     int64               `json:"nearestTicketExpirySeconds,omitempty"`
	OldestVerificationAgeSeconds   int64               `json:"oldestVerificationAgeSeconds,omitempty"`
	MeasurementDigests             []string            `json:"measurementDigests"`
	MeasurementVersions            []string            `json:"measurementVersions"`
	LastDiscovery                  OperationDiagnostic `json:"lastDiscovery"`
	LastEvidence                   OperationDiagnostic `json:"lastEvidence"`
	LastColdPath                   OperationDiagnostic `json:"lastColdPath"`
	LastInvoke                     OperationDiagnostic `json:"lastInvoke"`
	LastProtocolFailure            OperationDiagnostic `json:"lastProtocolFailure"`
	LastTicketStarvation           OperationDiagnostic `json:"lastTicketStarvation"`
	AttestationFailures            map[string]uint64   `json:"attestationFailures"`
	TicketStarvation               uint64              `json:"ticketStarvation"`
	ColdPaths                      uint64              `json:"coldPaths"`
	InvokeRateLimited              uint64              `json:"invokeRateLimited"`
	InvokeUnavailable              uint64              `json:"invokeUnavailable"`
	InvokeNotFound                 uint64              `json:"invokeNotFound"`
	InvokeTransportErrors          uint64              `json:"invokeTransportErrors"`
	ProtocolFailures               uint64              `json:"protocolFailures"`
}

type DiagnosticsSnapshot struct {
	CredentialCapacity    int               `json:"credentialCapacity"`
	CredentialHits        uint64            `json:"credentialHits"`
	CredentialMisses      uint64            `json:"credentialMisses"`
	CredentialExpired     uint64            `json:"credentialExpired"`
	CredentialEvicted     uint64            `json:"credentialEvicted"`
	CredentialRejected    uint64            `json:"credentialRejected"`
	PoolTargets           int64             `json:"poolTargets"`
	PoolTargetCapacity    int               `json:"poolTargetCapacity"`
	TargetRejections      uint64            `json:"targetRejections"`
	EvidenceInFlight      int64             `json:"evidenceInFlight"`
	EvidenceCapacity      int               `json:"evidenceCapacity"`
	EvidenceRejected      uint64            `json:"evidenceRejected"`
	GeneratedAt           time.Time         `json:"generatedAt"`
	CredentialPools       int               `json:"credentialPools"`
	ActiveCredentialPools int               `json:"activeCredentialPools"`
	BYOKCredentialPools   int               `json:"byokCredentialPools"`
	Chutes                []ChuteDiagnostic `json:"chutes"`
}

type operationState struct {
	value atomic.Pointer[OperationDiagnostic]
}

func (s *operationState) set(status int, latency time.Duration, err error) {
	value := &OperationDiagnostic{
		At:        time.Now().UTC(),
		Status:    status,
		LatencyMS: latency.Milliseconds(),
		Error:     diagnosticErrorClass(err),
	}
	s.value.Store(value)
}

func (s *operationState) get() OperationDiagnostic {
	if value := s.value.Load(); value != nil {
		return *value
	}
	return OperationDiagnostic{}
}

type chuteMetrics struct {
	lastUsed              atomic.Int64
	modelsMu              sync.RWMutex
	models                map[string]struct{}
	discovery             operationState
	evidence              operationState
	coldPath              operationState
	invoke                operationState
	protocolFailure       operationState
	starvation            operationState
	failures              sync.Map
	ticketStarvation      atomic.Uint64
	coldPaths             atomic.Uint64
	invokeRateLimited     atomic.Uint64
	invokeUnavailable     atomic.Uint64
	invokeNotFound        atomic.Uint64
	invokeTransportErrors atomic.Uint64
	protocolFailures      atomic.Uint64
}

type diagnostics struct {
	credentialHits     atomic.Uint64
	credentialMisses   atomic.Uint64
	credentialExpired  atomic.Uint64
	credentialEvicted  atomic.Uint64
	credentialRejected atomic.Uint64
	registryMu         sync.Mutex
	registrySize       int
	chutes             sync.Map
	poolTargets        atomic.Int64
	targetRejections   atomic.Uint64
	evidenceInFlight   atomic.Int64
	evidenceRejected   atomic.Uint64
}

type poolHealth struct {
	CredentialPools                int
	CredentialPoolsInRefillBackoff int
	VerifiedInstances              int
	KeyPossessionVerifiedInstances int
	UsableTickets                  int
	CooldownInstances              int
	RefillBackoffSeconds           int64
	NearestTicketExpirySeconds     int64
	OldestVerificationAgeSeconds   int64
	MeasurementDigests             []string
	MeasurementVersions            []string
	verifiedBindings               map[string]struct{}
	keyPossessionBindings          map[string]struct{}
	cooldownInstanceIDs            map[string]struct{}
}

func (d *diagnostics) chute(chuteID string) *chuteMetrics {
	d.registryMu.Lock()
	defer d.registryMu.Unlock()
	if value, ok := d.chutes.Load(chuteID); ok {
		value.(*chuteMetrics).lastUsed.Store(time.Now().UnixNano())
		return value.(*chuteMetrics)
	}
	if d.registrySize >= maximumDiagnosticChutes {
		var oldestKey any
		var oldest int64
		d.chutes.Range(func(key, value any) bool {
			lastUsed := value.(*chuteMetrics).lastUsed.Load()
			if oldestKey == nil || lastUsed < oldest {
				oldestKey, oldest = key, lastUsed
			}
			return true
		})
		if oldestKey != nil {
			d.chutes.Delete(oldestKey)
			d.registrySize--
		}
	}
	created := &chuteMetrics{models: make(map[string]struct{})}
	created.lastUsed.Store(time.Now().UnixNano())
	value, _ := d.chutes.LoadOrStore(chuteID, created)
	d.registrySize++
	return value.(*chuteMetrics)
}

func (d *diagnostics) registerModel(chuteID, model string) {
	metrics := d.chute(chuteID)
	metrics.modelsMu.Lock()
	if len(metrics.models) < maximumDiagnosticModels {
		metrics.models[model] = struct{}{}
	}
	metrics.modelsMu.Unlock()
}

const maximumDiagnosticChutes = 512
const maximumDiagnosticModels = 64

func (d *diagnostics) recordDiscovery(chuteID string, status int, latency time.Duration, err error) {
	d.chute(chuteID).discovery.set(status, latency, err)
}

func (d *diagnostics) recordEvidence(chuteID string, status int, latency time.Duration, err error) {
	d.chute(chuteID).evidence.set(status, latency, err)
}

func (d *diagnostics) recordColdPath(chuteID string, latency time.Duration, err error) {
	metrics := d.chute(chuteID)
	metrics.coldPaths.Add(1)
	metrics.coldPath.set(0, latency, err)
}

func (d *diagnostics) recordAttestationFailure(chuteID, category string) {
	metrics := d.chute(chuteID)
	value, _ := metrics.failures.LoadOrStore(category, &atomic.Uint64{})
	value.(*atomic.Uint64).Add(1)
}

func (d *diagnostics) recordTicketStarvation(chuteID string) {
	metrics := d.chute(chuteID)
	metrics.ticketStarvation.Add(1)
	metrics.starvation.set(0, 0, ErrNoUsableTicket)
}

func (d *diagnostics) recordTicketAvailable(chuteID string) {
	d.chute(chuteID).starvation.set(0, 0, nil)
}

func (d *diagnostics) recordInvoke(chuteID string, status int, err error) {
	metrics := d.chute(chuteID)
	metrics.invoke.set(status, 0, err)
	if err != nil {
		metrics.invokeTransportErrors.Add(1)
		return
	}
	switch status {
	case 404, 410:
		metrics.invokeNotFound.Add(1)
	case 429:
		metrics.invokeRateLimited.Add(1)
	case 500, 502, 503, 504:
		metrics.invokeUnavailable.Add(1)
	}
}

func (d *diagnostics) recordProtocolFailure(chuteID string) {
	metrics := d.chute(chuteID)
	metrics.protocolFailures.Add(1)
	metrics.protocolFailure.set(0, 0, ErrInvalidE2EEResponse)
}

func (d *diagnostics) snapshot(health map[string]poolHealth) DiagnosticsSnapshot {
	result := DiagnosticsSnapshot{GeneratedAt: time.Now().UTC(), Chutes: []ChuteDiagnostic{}}
	d.chutes.Range(func(key, value any) bool {
		chuteID := key.(string)
		metrics := value.(*chuteMetrics)
		metrics.modelsMu.RLock()
		models := make([]string, 0, len(metrics.models))
		for model := range metrics.models {
			models = append(models, model)
		}
		metrics.modelsMu.RUnlock()
		sort.Strings(models)
		failures := make(map[string]uint64)
		metrics.failures.Range(func(key, value any) bool {
			failures[key.(string)] = value.(*atomic.Uint64).Load()
			return true
		})
		state := health[chuteID]
		result.Chutes = append(result.Chutes, ChuteDiagnostic{
			ChuteID:                        chuteID,
			UpstreamModels:                 models,
			CredentialPools:                state.CredentialPools,
			CredentialPoolsInRefillBackoff: state.CredentialPoolsInRefillBackoff,
			VerifiedInstances:              state.VerifiedInstances,
			KeyPossessionVerifiedInstances: state.KeyPossessionVerifiedInstances,
			UsableTickets:                  state.UsableTickets,
			CooldownInstances:              state.CooldownInstances,
			RefillBackoffSeconds:           state.RefillBackoffSeconds,
			NearestTicketExpirySeconds:     state.NearestTicketExpirySeconds,
			OldestVerificationAgeSeconds:   state.OldestVerificationAgeSeconds,
			MeasurementDigests:             state.MeasurementDigests,
			MeasurementVersions:            state.MeasurementVersions,
			LastDiscovery:                  metrics.discovery.get(),
			LastEvidence:                   metrics.evidence.get(),
			LastColdPath:                   metrics.coldPath.get(),
			LastInvoke:                     metrics.invoke.get(),
			LastProtocolFailure:            metrics.protocolFailure.get(),
			LastTicketStarvation:           metrics.starvation.get(),
			AttestationFailures:            failures,
			TicketStarvation:               metrics.ticketStarvation.Load(),
			ColdPaths:                      metrics.coldPaths.Load(),
			InvokeRateLimited:              metrics.invokeRateLimited.Load(),
			InvokeUnavailable:              metrics.invokeUnavailable.Load(),
			InvokeNotFound:                 metrics.invokeNotFound.Load(),
			InvokeTransportErrors:          metrics.invokeTransportErrors.Load(),
			ProtocolFailures:               metrics.protocolFailures.Load(),
		})
		return true
	})
	sort.Slice(result.Chutes, func(left, right int) bool {
		return result.Chutes[left].ChuteID < result.Chutes[right].ChuteID
	})
	return result
}

func diagnosticErrorClass(err error) string {
	if err == nil {
		return ""
	}
	var statusError *httpStatusError
	if errors.As(err, &statusError) {
		if statusError.StatusCode == 429 {
			return "rate_limited"
		}
		if statusError.StatusCode >= 500 {
			return "upstream_unavailable"
		}
		return "upstream_rejected"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, ErrMeasurementPolicy) {
		return "measurement_policy"
	}
	if errors.Is(err, ErrGPUAttestationFailed) {
		return "gpu_attestation"
	}
	if errors.Is(err, ErrAttestationFailed) {
		return "tdx_attestation"
	}
	if errors.Is(err, ErrInvalidE2EERequest) || errors.Is(err, ErrInvalidE2EEResponse) {
		return "protocol"
	}
	if errors.Is(err, ErrNoUsableTicket) {
		return "capacity"
	}
	return "transport"
}
