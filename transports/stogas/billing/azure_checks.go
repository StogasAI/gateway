package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

const azureCheckQueryTimeout = 5 * time.Second

// AzureDeployment is one deployment that an Azure account lists, as gateways and Control's
// discovery both report it: its lowercase resource ID and, trimmed, the model format, name and
// version and the SKU that it serves, its provisioning state and its version upgrade option,
// empty when Azure left one out.
type AzureDeployment struct {
	ID             string `json:"id"`
	ModelFormat    string `json:"modelFormat"`
	ModelName      string `json:"modelName"`
	ModelVersion   string `json:"modelVersion"`
	SkuName        string `json:"skuName"`
	State          string `json:"state"`
	VersionUpgrade string `json:"versionUpgrade"`
}

// AzureClaim is a gateway's attempt to claim the next check of an Azure credential's targets.
// VerifiedAt is the last confirmation, zero when there was none, and StartedAt the database time
// that a check claimed now starts from. Unavailable maps the selected targets that are out of
// service to why: missing, changed, failed or shadowed.
type AzureClaim struct {
	Claimed     bool
	VerifiedAt  time.Time
	StartedAt   time.Time
	Unavailable map[string]string
}

// AzureCheckResult reports a recorded check. Superseded means that a newer check or discovery
// confirmed the targets first, so this one changed nothing, and Changed that a discovery used an
// application that the credential no longer holds. Unavailable maps the selected targets that are
// out of service afterwards to why.
type AzureCheckResult struct {
	Superseded  bool
	Changed     bool
	Unavailable map[string]string
}

// ClaimAzureCheck claims the next check of an Azure credential's targets when their last
// confirmation is at least staleAfter old and no other gateway holds the claim.
func (s *Service) ClaimAzureCheck(ctx context.Context, byokID string, staleAfter time.Duration) (AzureClaim, error) {
	if s == nil || s.db == nil {
		return AzureClaim{}, ErrGatewayUnavailable
	}
	queryCtx, cancel := context.WithTimeout(ctx, azureCheckQueryTimeout)
	defer cancel()
	var claim AzureClaim
	var verifiedAt pgtype.Timestamptz
	var unavailable []byte
	if err := s.db.pool.QueryRow(queryCtx, s.claimAzureCheckQuery, byokID, staleAfter.Seconds()).
		Scan(&claim.Claimed, &verifiedAt, &claim.StartedAt, &unavailable); err != nil {
		return AzureClaim{}, fmt.Errorf("%w: claim Azure check: %v", ErrGatewayUnavailable, err)
	}
	if err := json.Unmarshal(unavailable, &claim.Unavailable); err != nil {
		return AzureClaim{}, fmt.Errorf("%w: claim Azure check: %v", ErrGatewayUnavailable, err)
	}
	if verifiedAt.Valid {
		claim.VerifiedAt = verifiedAt.Time
	}
	return claim, nil
}

// RecordAzureCheck records the deployments that a check read from Azure after startedAt.
func (s *Service) RecordAzureCheck(ctx context.Context, byokID string, startedAt time.Time, deployments []AzureDeployment) (AzureCheckResult, error) {
	if s == nil || s.db == nil {
		return AzureCheckResult{}, ErrGatewayUnavailable
	}
	if deployments == nil {
		deployments = []AzureDeployment{}
	}
	payload, err := json.Marshal(deployments)
	if err != nil {
		return AzureCheckResult{}, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, azureCheckQueryTimeout)
	defer cancel()
	var outcome string
	var unavailable []byte
	if err := s.db.pool.QueryRow(queryCtx, s.recordAzureCheckQuery, byokID, startedAt, string(payload)).
		Scan(&outcome, &unavailable); err != nil {
		return AzureCheckResult{}, fmt.Errorf("%w: record Azure check: %v", ErrGatewayUnavailable, err)
	}
	result := AzureCheckResult{Superseded: outcome == "superseded"}
	switch outcome {
	case "ok", "superseded":
	default:
		return AzureCheckResult{}, fmt.Errorf("%w: record Azure check: %s", ErrGatewayUnavailable, outcome)
	}
	if err := json.Unmarshal(unavailable, &result.Unavailable); err != nil {
		return AzureCheckResult{}, fmt.Errorf("%w: record Azure check: %v", ErrGatewayUnavailable, err)
	}
	return result, nil
}

// StopAzureTarget stops a target whose reply named servedModel, another model version than the
// target's, and asks for a discovery. It reports whether the target stopped; one that
// already stopped stays as it is.
func (s *Service) StopAzureTarget(ctx context.Context, byokID, bindingID, servedModel string) (bool, error) {
	if s == nil || s.db == nil {
		return false, ErrGatewayUnavailable
	}
	queryCtx, cancel := context.WithTimeout(ctx, azureCheckQueryTimeout)
	defer cancel()
	var stopped bool
	if err := s.db.pool.QueryRow(queryCtx, s.stopAzureTargetQuery, byokID, bindingID, servedModel).Scan(&stopped); err != nil {
		return false, fmt.Errorf("%w: stop Azure target: %v", ErrGatewayUnavailable, err)
	}
	return stopped, nil
}

// AzureDiscoveryResult is what a gateway's discovery of an Azure credential's targets found, as
// azure_save_discovery reads it: the targets, already encoded, and every deployment that the
// account lists.
type AzureDiscoveryResult struct {
	Bindings    json.RawMessage
	Deployments []AzureDeployment
}

// parameters encodes a discovery for the database, as two nulls when there is none.
func (d *AzureDiscoveryResult) parameters() (bindings, deployments pgtype.Text, err error) {
	if d == nil {
		return pgtype.Text{}, pgtype.Text{}, nil
	}
	if !json.Valid(d.Bindings) {
		return pgtype.Text{}, pgtype.Text{}, fmt.Errorf("%w: invalid Azure discovery", ErrGatewayUnavailable)
	}
	listed := d.Deployments
	if listed == nil {
		listed = []AzureDeployment{}
	}
	payload, err := json.Marshal(listed)
	if err != nil {
		return pgtype.Text{}, pgtype.Text{}, err
	}
	return pgtype.Text{String: string(d.Bindings), Valid: true}, pgtype.Text{String: string(payload), Valid: true}, nil
}

// ClaimAzureDiscovery claims the discovery of a customer-encrypted Azure credential's targets when
// it is due and no other gateway holds the credential's claim. It returns the database time that
// the discovery starts from.
func (s *Service) ClaimAzureDiscovery(ctx context.Context, byokID string) (bool, time.Time, error) {
	if s == nil || s.db == nil {
		return false, time.Time{}, ErrGatewayUnavailable
	}
	queryCtx, cancel := context.WithTimeout(ctx, azureCheckQueryTimeout)
	defer cancel()
	var claimed bool
	var startedAt time.Time
	if err := s.db.pool.QueryRow(queryCtx, s.claimAzureDiscoveryQuery, byokID).Scan(&claimed, &startedAt); err != nil {
		return false, time.Time{}, fmt.Errorf("%w: claim Azure discovery: %v", ErrGatewayUnavailable, err)
	}
	return claimed, startedAt, nil
}

// RecordAzureDiscovery records a discovery that started at startedAt with the application that
// envelope holds: failure is empty when Azure accepted the application, and discovery is nil when
// it read no deployments. A credential whose envelope changed meanwhile records nothing, which
// Changed reports.
func (s *Service) RecordAzureDiscovery(ctx context.Context, byokID string, startedAt time.Time, envelope string, failure string, discovery *AzureDiscoveryResult) (AzureCheckResult, error) {
	if s == nil || s.db == nil {
		return AzureCheckResult{}, ErrGatewayUnavailable
	}
	var message pgtype.Text
	if failure != "" {
		message = pgtype.Text{String: failure, Valid: true}
	}
	bindings, deployments, err := discovery.parameters()
	if err != nil {
		return AzureCheckResult{}, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, azureCheckQueryTimeout)
	defer cancel()
	var outcome string
	var unavailable []byte
	if err := s.db.pool.QueryRow(queryCtx, s.recordAzureDiscoveryQuery, byokID, startedAt, envelope, message, bindings, deployments).
		Scan(&outcome, &unavailable); err != nil {
		return AzureCheckResult{}, fmt.Errorf("%w: record Azure discovery: %v", ErrGatewayUnavailable, err)
	}
	result := AzureCheckResult{Changed: outcome == "changed"}
	switch outcome {
	case "ok", "changed":
	default:
		return AzureCheckResult{}, fmt.Errorf("%w: record Azure discovery: %s", ErrGatewayUnavailable, outcome)
	}
	if err := json.Unmarshal(unavailable, &result.Unavailable); err != nil {
		return AzureCheckResult{}, fmt.Errorf("%w: record Azure discovery: %v", ErrGatewayUnavailable, err)
	}
	return result, nil
}
