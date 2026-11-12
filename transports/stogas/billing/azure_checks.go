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
// version and the SKU that it serves and its provisioning state, empty when Azure left one out.
type AzureDeployment struct {
	ID           string `json:"id"`
	ModelFormat  string `json:"modelFormat"`
	ModelName    string `json:"modelName"`
	ModelVersion string `json:"modelVersion"`
	SkuName      string `json:"skuName"`
	State        string `json:"state"`
}

// AzureClaim is a gateway's attempt to claim the next check of an Azure credential's targets.
// VerifiedAt is the last confirmation, zero when there was none, and StartedAt the database time
// that a check claimed now starts from.
type AzureClaim struct {
	Claimed    bool
	VerifiedAt time.Time
	StartedAt  time.Time
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
	if err := s.db.pool.QueryRow(queryCtx, s.claimAzureCheckQuery, byokID, staleAfter.Seconds()).
		Scan(&claim.Claimed, &verifiedAt, &claim.StartedAt); err != nil {
		return AzureClaim{}, fmt.Errorf("%w: claim Azure check: %v", ErrGatewayUnavailable, err)
	}
	if verifiedAt.Valid {
		claim.VerifiedAt = verifiedAt.Time
	}
	return claim, nil
}

// RecordAzureCheck records the deployments that a check read from Azure after startedAt, which
// stops the selected targets that they no longer serve. A newer check or discovery that confirmed
// the targets first leaves this one nothing to change.
func (s *Service) RecordAzureCheck(ctx context.Context, byokID string, startedAt time.Time, deployments []AzureDeployment) error {
	if s == nil || s.db == nil {
		return ErrGatewayUnavailable
	}
	if deployments == nil {
		deployments = []AzureDeployment{}
	}
	payload, err := json.Marshal(deployments)
	if err != nil {
		return err
	}
	queryCtx, cancel := context.WithTimeout(ctx, azureCheckQueryTimeout)
	defer cancel()
	var outcome string
	if err := s.db.pool.QueryRow(queryCtx, s.recordAzureCheckQuery, byokID, startedAt, string(payload)).Scan(&outcome); err != nil {
		return fmt.Errorf("%w: record Azure check: %v", ErrGatewayUnavailable, err)
	}
	if outcome != "ok" && outcome != "superseded" {
		return fmt.Errorf("%w: record Azure check: %s", ErrGatewayUnavailable, outcome)
	}
	return nil
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
// changed reports.
func (s *Service) RecordAzureDiscovery(ctx context.Context, byokID string, startedAt time.Time, envelope string, failure string, discovery *AzureDiscoveryResult) (changed bool, err error) {
	if s == nil || s.db == nil {
		return false, ErrGatewayUnavailable
	}
	var message pgtype.Text
	if failure != "" {
		message = pgtype.Text{String: failure, Valid: true}
	}
	bindings, deployments, err := discovery.parameters()
	if err != nil {
		return false, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, azureCheckQueryTimeout)
	defer cancel()
	var outcome string
	if err := s.db.pool.QueryRow(queryCtx, s.recordAzureDiscoveryQuery, byokID, startedAt, envelope, message, bindings, deployments).Scan(&outcome); err != nil {
		return false, fmt.Errorf("%w: record Azure discovery: %v", ErrGatewayUnavailable, err)
	}
	if outcome != "ok" && outcome != "changed" {
		return false, fmt.Errorf("%w: record Azure discovery: %s", ErrGatewayUnavailable, outcome)
	}
	return outcome == "changed", nil
}
