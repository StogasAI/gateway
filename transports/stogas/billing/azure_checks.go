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

// RefuseAzureCheck records that Azure refused a check that started at startedAt. Unless a
// discovery already found the credential failing, its discovery becomes due at once and records
// why on the credential.
func (s *Service) RefuseAzureCheck(ctx context.Context, byokID string, startedAt time.Time) error {
	if s == nil || s.db == nil {
		return ErrGatewayUnavailable
	}
	queryCtx, cancel := context.WithTimeout(ctx, azureCheckQueryTimeout)
	defer cancel()
	var outcome string
	if err := s.db.pool.QueryRow(queryCtx, s.recordAzureCheckQuery, byokID, startedAt, nil).Scan(&outcome); err != nil {
		return fmt.Errorf("%w: record Azure refusal: %v", ErrGatewayUnavailable, err)
	}
	if outcome != "ok" && outcome != "superseded" {
		return fmt.Errorf("%w: record Azure refusal: %s", ErrGatewayUnavailable, outcome)
	}
	return nil
}

// AzureDiscoveryResult is what a gateway's discovery of an Azure credential's targets found, as
// azure_save_discovery reads it: the targets, already encoded, every deployment that the account
// lists, and whether the account holds each account option that Azure reports.
type AzureDiscoveryResult struct {
	Bindings       json.RawMessage
	Deployments    []AzureDeployment
	AccountOptions map[string]bool
}

// parameters encodes a discovery for the database, as nulls when there is none.
func (d *AzureDiscoveryResult) parameters() (bindings, deployments, accountOptions pgtype.Text, err error) {
	if d == nil {
		return bindings, deployments, accountOptions, nil
	}
	if !json.Valid(d.Bindings) {
		return bindings, deployments, accountOptions, fmt.Errorf("%w: invalid Azure discovery", ErrGatewayUnavailable)
	}
	listed, options := d.Deployments, d.AccountOptions
	if listed == nil {
		listed = []AzureDeployment{}
	}
	if options == nil {
		options = map[string]bool{}
	}
	payload, err := json.Marshal(listed)
	if err != nil {
		return bindings, deployments, accountOptions, err
	}
	reported, err := json.Marshal(options)
	if err != nil {
		return bindings, deployments, accountOptions, err
	}
	return pgtype.Text{String: string(d.Bindings), Valid: true}, pgtype.Text{String: string(payload), Valid: true},
		pgtype.Text{String: string(reported), Valid: true}, nil
}

// AzureDiscoveryClaim is a gateway's claim of the discovery of a customer-encrypted Azure
// credential's targets. StartedAt is the database time that the discovery starts from.
type AzureDiscoveryClaim struct {
	Claimed      bool
	StartedAt    time.Time
	claimedUntil time.Time
}

// ClaimAzureDiscovery claims the discovery of a customer-encrypted Azure credential's targets when
// it is due and no other gateway holds the credential's claim.
func (s *Service) ClaimAzureDiscovery(ctx context.Context, byokID string) (AzureDiscoveryClaim, error) {
	if s == nil || s.db == nil {
		return AzureDiscoveryClaim{}, ErrGatewayUnavailable
	}
	queryCtx, cancel := context.WithTimeout(ctx, azureCheckQueryTimeout)
	defer cancel()
	var claim AzureDiscoveryClaim
	var claimedUntil pgtype.Timestamptz
	if err := s.db.pool.QueryRow(queryCtx, s.claimAzureDiscoveryQuery, byokID).Scan(&claim.Claimed, &claim.StartedAt, &claimedUntil); err != nil {
		return AzureDiscoveryClaim{}, fmt.Errorf("%w: claim Azure discovery: %v", ErrGatewayUnavailable, err)
	}
	if claim.Claimed {
		if !claimedUntil.Valid {
			return AzureDiscoveryClaim{}, fmt.Errorf("%w: claim Azure discovery: no claim", ErrGatewayUnavailable)
		}
		claim.claimedUntil = claimedUntil.Time
	}
	return claim, nil
}

// RecordAzureDiscovery records a claimed discovery with the application that envelope holds:
// failure is empty when Azure accepted the application, and discovery is nil when it read no
// deployments. A credential whose envelope changed meanwhile records nothing, which changed reports.
func (s *Service) RecordAzureDiscovery(ctx context.Context, byokID string, claim AzureDiscoveryClaim, envelope string, failure string, discovery *AzureDiscoveryResult) (changed bool, err error) {
	if s == nil || s.db == nil || !claim.Claimed {
		return false, ErrGatewayUnavailable
	}
	var message pgtype.Text
	if failure != "" {
		message = pgtype.Text{String: failure, Valid: true}
	}
	bindings, deployments, accountOptions, err := discovery.parameters()
	if err != nil {
		return false, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, azureCheckQueryTimeout)
	defer cancel()
	var outcome string
	if err := s.db.pool.QueryRow(queryCtx, s.recordAzureDiscoveryQuery, byokID, claim.StartedAt, claim.claimedUntil, envelope, message, bindings, deployments, accountOptions).Scan(&outcome); err != nil {
		return false, fmt.Errorf("%w: record Azure discovery: %v", ErrGatewayUnavailable, err)
	}
	if outcome != "ok" && outcome != "changed" {
		return false, fmt.Errorf("%w: record Azure discovery: %s", ErrGatewayUnavailable, outcome)
	}
	return outcome == "changed", nil
}
