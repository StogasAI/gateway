package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	verifier "github.com/StogasAI/verifier/go"
	"github.com/maximhq/bifrost/transports/stogas/confidential/clock"
)

const (
	evidencePollInterval       = 2 * time.Minute
	evidenceAttemptTimeout     = 5 * time.Second
	evidenceAcquisitionTimeout = 15 * time.Second
	evidenceBodyLimit          = 16 * 1024 * 1024
)

type approvedGateway struct {
	ID      string `json:"release_id"`
	Release struct {
		Measurement string `json:"measurement"`
		Sequence    uint64 `json:"sequence"`
	} `json:"release"`
}

type approvedCatalog struct {
	ID      string `json:"release_id"`
	Release struct {
		Sequence               uint64 `json:"sequence"`
		MinimumGatewaySequence uint64 `json:"minimum_gateway_sequence"`
		RuntimeDigest          string `json:"runtime_digest"`
		RuntimeSizeBytes       int64  `json:"runtime_size_bytes"`
		PublicDigest           string `json:"public_digest"`
		PublicSizeBytes        int64  `json:"public_size_bytes"`
	} `json:"release"`
}

type evidenceSummary struct {
	Gateways  []approvedGateway `json:"gateways"`
	Catalogs  []approvedCatalog `json:"catalogs"`
	Approvals struct {
		HardwarePolicySHA256 string `json:"hardware_policy_sha256"`
	} `json:"approvals"`
}

type evidenceOrigin struct {
	url  string
	etag string
	// An ETag is usable only while its representation is the installed snapshot.
	digest [sha256.Size]byte
}

// One maintenance owner performs all fetches. Request admission reads the last
// appraisal and its actual validity deadline, never waits for this network work.
type currentEvidence struct {
	verifier        *verifier.Evidence
	snapshot        *verifier.EvidenceSnapshot
	summary         evidenceSummary
	client          *http.Client
	origins         []evidenceOrigin
	installed       [sha256.Size]byte
	rejectedCatalog catalogRejection
	now             func() time.Time
	// now is trusted only while NTS keeps the guest clock synchronized.
	synchronized func() bool
}

func newCurrentEvidence(environment string) (*currentEvidence, error) {
	var origins []evidenceOrigin
	switch environment {
	case "production", "prod":
		environment = "prod"
		origins = []evidenceOrigin{{url: "https://evidence.stogas.ai"}, {url: "https://evidence2.stogas.ai"}}
	case "staging":
		origins = []evidenceOrigin{{url: "https://evidence-staging.stogas.ai"}, {url: "https://evidence2-staging.stogas.ai"}}
	default:
		return nil, errors.New("confidential evidence requires a deployment environment")
	}
	core, err := verifier.NewEvidence(verifier.EvidenceOptions{Environment: environment})
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = 16 * 1024
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("evidence redirects are not permitted")
	}}
	return &currentEvidence{verifier: core, client: client, origins: origins, now: time.Now, synchronized: clock.Synchronized}, nil
}

func (e *currentEvidence) close() {
	if e.snapshot != nil {
		_ = e.snapshot.Close()
	}
	_ = e.verifier.Close()
	e.client.CloseIdleConnections()
}

// refresh asks every origin, so one stale or withholding origin cannot hide a
// newer copy such as a withdrawal; the verifier rejects older and conflicting
// copies. An unavailable origin alone preserves valid installed state. A complete
// authenticated withdrawal remains installed even when check rejects this boot.
// Invalid delivery cannot erase learned CRLs or root-key retirement.
func (e *currentEvidence) refresh(parent context.Context, check func(*verifier.EvidenceSnapshot, evidenceSummary) error) error {
	ctx, cancel := context.WithTimeout(parent, evidenceAcquisitionTimeout)
	defer cancel()
	var failures []error
	var appraisal error
	answered := false
	for i := range e.origins {
		if err := e.fetch(ctx, &e.origins[i]); err != nil {
			failures = append(failures, err)
		} else {
			answered = true
		}
		// A rejected candidate can still authenticate a revocation or retired key.
		// Appraise before asking the next origin so admission reacts immediately.
		if e.snapshot != nil {
			appraisal = check(e.snapshot, e.summary)
		}
	}
	if answered && appraisal == nil {
		return nil
	}
	return errors.Join(append(failures, appraisal)...)
}

func (e *currentEvidence) fetch(parent context.Context, origin *evidenceOrigin) error {
	ctx, cancel := context.WithTimeout(parent, evidenceAttemptTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.url+"/evidence/latest.json", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	conditional := e.snapshot != nil && origin.digest == e.installed && origin.etag != ""
	if conditional {
		request.Header.Set("If-None-Match", origin.etag)
	}
	response, err := e.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		if !conditional {
			return errors.New("evidence returned an unsolicited 304")
		}
		return nil
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("evidence returned HTTP %d", response.StatusCode)
	}
	bytes, err := io.ReadAll(io.LimitReader(response.Body, evidenceBodyLimit+1))
	if err != nil {
		return err
	}
	if len(bytes) > evidenceBodyLimit {
		return errors.New("evidence exceeds decoded size limit")
	}
	digest := sha256.Sum256(bytes)
	etag := response.Header.Get("ETag")
	if len(etag) > 512 {
		etag = ""
	}
	// Origins serve the same bytes under different ETags; reverify only new bytes.
	if e.snapshot != nil && digest == e.installed {
		origin.digest, origin.etag = digest, etag
		return nil
	}
	candidate, err := e.verifier.RefreshAt(bytes, e.now())
	if err != nil {
		return err
	}
	summaryBytes, err := candidate.Summary()
	var summary evidenceSummary
	if err == nil {
		err = json.Unmarshal(summaryBytes, &summary)
	}
	if err != nil {
		_ = candidate.Close()
		return err
	}
	previous := e.snapshot
	e.snapshot, e.summary, e.installed = candidate, summary, digest
	origin.digest, origin.etag = digest, etag
	if previous != nil {
		_ = previous.Close()
	}
	return nil
}

func (summary evidenceSummary) gateway(measurement string) (approvedGateway, bool) {
	var selected approvedGateway
	for _, gateway := range summary.Gateways {
		if gateway.Release.Measurement == measurement && (selected.ID == "" || gateway.Release.Sequence > selected.Release.Sequence) {
			selected = gateway
		}
	}
	return selected, selected.ID != ""
}

func (summary evidenceSummary) catalog(gatewayID string) (approvedCatalog, bool) {
	var gateway *approvedGateway
	for i := range summary.Gateways {
		if summary.Gateways[i].ID == gatewayID {
			gateway = &summary.Gateways[i]
			break
		}
	}
	if gateway == nil {
		return approvedCatalog{}, false
	}
	var selected approvedCatalog
	for _, catalog := range summary.Catalogs {
		if catalog.Release.MinimumGatewaySequence <= gateway.Release.Sequence && (selected.ID == "" || catalog.Release.Sequence > selected.Release.Sequence) {
			selected = catalog
		}
	}
	return selected, selected.ID != ""
}
