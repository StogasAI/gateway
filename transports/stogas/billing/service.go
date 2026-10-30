package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/money"
	"github.com/maximhq/bifrost/transports/stogas/policy"
	"io"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/sync/singleflight"
)

const (
	authorizeTimeout = 1500 * time.Millisecond
	// Waiting in the organization's queue and for a connection ends this long
	// before the authorization deadline, so a statement that starts can finish.
	// One cut off loses its connection and needs a close, which under overload
	// costs the pool more than the requests it fails.
	authorizeStatementReserve  = 250 * time.Millisecond
	holdSettlementExpiryBuffer = 20 * time.Minute

	// GatewayRequestLifetime bounds direct inference, so a hold that outlives it
	// by holdSettlementExpiryBuffer failed to settle and raises an alert.
	GatewayRequestLifetime = time.Hour
	ManagedUpstreamByok    = "stogas"
)

var ErrAuthorizationAbsent = errors.New("Authorization not found")

const authorizeHoldArguments = `
  $1::text,
  $2::text,
  $3::text,
  $4::text,
  $5::uuid,
  $6::uuid,
  $7::text,
  $8::text,
  $9::numeric,
  $10::timestamptz,
  $11::text,
  $12::jsonb,
  $13::text,
  $14::timestamptz,
  $15::numeric,
  $16::timestamptz,
  $17::bigint,
  $18::jsonb,
  $19::jsonb,
  $20::jsonb,
  $21::numeric,
  $22::text,
  $23::uuid,
  $24::uuid[]
`

const authorizeHoldColumns = "result, hold_id, user_id, key_id, grant_id, organization_id, authorized_billed_cost_usd, created_at, expires_at, upstream_byok, upstream_byok_binding, config_current, wait_ms, requests_per_second, tax_rate, tax_rate_id"

const closeRequestArguments = `
  $1::uuid,
  $2::text,
  $3::timestamptz
`

type authorizeRow struct {
	Result                  string
	HoldID                  *string
	UserID                  *string
	KeyID                   *string
	GrantID                 *string
	OrganizationID          *string
	AuthorizedBilledCostUSD *string
	CreatedAt               *time.Time
	ExpiresAt               *time.Time
	UpstreamByok            *string
	UpstreamByokBinding     *string
	ConfigCurrent           bool
	// WaitMS is how long an admitted request waits to start, or how long a
	// refusal lasts. A refusal without it never ends by waiting.
	WaitMS *int64
	// RequestsPerSecond is the organization's platform rate, which results that
	// checked it report.
	RequestsPerSecond *int32
	// TaxRate is the rate an admitted hold fixed for the request's tax, and
	// TaxRateID its row; nil when no tax applies.
	TaxRate   *string
	TaxRateID *string
}

func (r *authorizeRow) fields() []any {
	return []any{
		&r.Result, &r.HoldID, &r.UserID, &r.KeyID, &r.GrantID, &r.OrganizationID, &r.AuthorizedBilledCostUSD,
		&r.CreatedAt, &r.ExpiresAt, &r.UpstreamByok, &r.UpstreamByokBinding, &r.ConfigCurrent, &r.WaitMS,
		&r.RequestsPerSecond, &r.TaxRate, &r.TaxRateID,
	}
}

type Authorization struct {
	releaseFinalization     func()
	holdID                  string
	AuthorizedBilledCostUSD *money.USD
	CreatedAt               time.Time
	GrantID                 *string
	KeyID                   string
	OrganizationID          string
	ProductKey              string
	ProviderKey             string
	RequestID               string
	UserID                  string
	UpstreamByok            string
	UpstreamByokSecret      string
	AzureBinding            *AzureBinding
	UpstreamTargetJSON      string
	// PostgreSQL spreads an organization's requests over time at its platform
	// request rate: a request admitted beyond it calls no provider before
	// StartAt. A move keeps it.
	StartAt time.Time
	// taxRate is the hold's tax rate in units of 10^-8; zero charges no tax. A
	// move keeps it. The request's log reports it as PostgreSQL wrote it, with
	// the row that names its state and jurisdictions, nil when no tax applies.
	taxRate     int64
	taxRateText string
	taxRateID   *string
}

type UpstreamTarget struct {
	DeploymentType     string `json:"deploymentType"`
	Hosting            string `json:"hosting"`
	Model              string `json:"model"`
	ModelFormat        string `json:"modelFormat"`
	ModelVersion       string `json:"modelVersion"`
	ProcessingLocation string `json:"processingLocation"`
	StorageLocation    string `json:"storageLocation"`
}

type AzureBinding struct {
	DeploymentName     string `json:"deploymentName"`
	DeploymentType     string `json:"deploymentType"`
	Endpoint           string `json:"endpoint"`
	Hosting            string `json:"hosting"`
	ModelFormat        string `json:"modelFormat"`
	ModelName          string `json:"modelName"`
	ModelVersion       string `json:"modelVersion"`
	ProcessingLocation string `json:"processingLocation"`
	StorageLocation    string `json:"storageLocation"`
	TokenScope         string `json:"tokenScope"`
}

type azureBoundBinding struct {
	Binding AzureBinding `json:"binding"`
	Schema  string       `json:"schema"`
}

func parseAzureBoundBinding(raw string) (azureBoundBinding, error) {
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	value := azureBoundBinding{}
	if err := decoder.Decode(&value); err != nil {
		return azureBoundBinding{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return azureBoundBinding{}, errors.New("invalid Azure binding: trailing JSON")
	}
	if value.Schema != "stogas.azure-binding.v1" ||
		value.Binding.DeploymentName == "" ||
		value.Binding.DeploymentType == "" ||
		value.Binding.Endpoint == "" ||
		value.Binding.Hosting == "" ||
		value.Binding.ModelFormat == "" ||
		value.Binding.ModelName == "" ||
		value.Binding.ModelVersion == "" ||
		value.Binding.ProcessingLocation == "" ||
		value.Binding.StorageLocation == "" ||
		value.Binding.TokenScope == "" {
		return azureBoundBinding{}, errors.New("invalid Azure binding")
	}
	return value, nil
}

type Service struct {
	db                         *GatewayDB
	authorizeHoldQuery         string
	authorizeHoldsQuery        string
	closeRequestQuery          string
	keyConfigQuery             string
	toolQueries                chan struct{}
	keyConfigs                 keyConfigCache
	keyConfigFlights           singleflight.Group
	authorizations             authorizationActivity
	organizationQueues         organizationQueues
	credentialRequests         localRequestLimiter
	organizationRequests       localRequestLimiter
	organizationRates          organizationRates
	apiKeys                    verifiedAPIKeyCache
	refusals                   refusalCache
	rejectionLogs              rejectionLogBuffer
	finalizations              finalizationState
	underReservedSettlements   atomic.Uint64
	negativeBalanceSettlements atomic.Uint64
	settleQuery                string
	keepFailedLogQuery         string
	sanctionedSourceQuery      string
	sanctionedNetworksQuery    string
	// Each hold records the boot that owns it, so Control can release the
	// holds of a boot that stopped.
	nodeID                  string
	apiKeyPepper            string
	apiKeyPepperFingerprint string
	inferenceTokenPublicKey *inferenceTokenKey
	byok                    *byokDecryptor
}

type DiagnosticsSnapshot struct {
	KeyConfigCache PolicyCacheDiagnostics    `json:"keyConfigCache"`
	RedactionCache PolicyCacheDiagnostics    `json:"redactionCache"`
	RejectionLogs  RejectionLogDiagnostics   `json:"rejectionLogs"`
	Database       *DatabaseDiagnostics      `json:"database,omitempty"`
	LocalAdmission LocalAdmissionDiagnostics `json:"localAdmission"`
	Settlement     SettlementDiagnostics     `json:"settlement"`
	// APIKeyPepperFingerprint names the pepper that signs and hashes API keys.
	APIKeyPepperFingerprint string `json:"apiKeyPepperFingerprint,omitempty"`
}

func NewService(
	ctx context.Context,
	databaseURL string,
	databaseSchema string,
	apiKeyPepper string,
	byokEncryptionSecret string,
	inferenceTokenPublicKey string,
	nodeID string,
) (*Service, error) {
	publicKey, err := parseInferenceTokenPublicKey(inferenceTokenPublicKey)
	if err != nil {
		return nil, err
	}
	byok, err := newByokDecryptor(byokEncryptionSecret)
	if err != nil {
		return nil, err
	}
	db, err := NewGatewayDB(ctx, databaseURL, databaseSchema)
	if err != nil {
		return nil, err
	}

	service := &Service{
		db:                      db,
		authorizeHoldQuery:      db.functionQuery("authorize_gateway_hold", authorizeHoldColumns, authorizeHoldArguments),
		authorizeHoldsQuery:     db.functionQuery("authorize_gateway_holds", "ordinal, "+authorizeHoldColumns, "$1::jsonb, $2::uuid[]"),
		closeRequestQuery:       db.functionQuery("close_gateway_request", "*", closeRequestArguments),
		keyConfigQuery:          db.functionQuery("gateway_api_key_config", keyConfigColumns, keyConfigArguments),
		toolQueries:             make(chan struct{}, poolConns/3),
		settleQuery:             db.functionQuery("settle_gateway_request_logs", "request_id, result", "$1::json, $2::json"),
		keepFailedLogQuery:      db.functionQuery("keep_failed_gateway_request_log", "*", "$1::uuid, $2::json"),
		sanctionedSourceQuery:   db.functionQuery("gateway_sanctioned_networks_source", "*", ""),
		sanctionedNetworksQuery: db.functionQuery("gateway_sanctioned_networks", "first_address, last_address", ""),
		inferenceTokenPublicKey: publicKey,
		nodeID:                  nodeID,
		apiKeyPepper:            apiKeyPepper,
		apiKeyPepperFingerprint: apiKeyPepperFingerprint(apiKeyPepper),
		byok:                    byok,
	}
	if err := db.checkQueries(
		ctx,
		service.authorizeHoldQuery,
		service.authorizeHoldsQuery,
		service.closeRequestQuery,
		service.keyConfigQuery,
		service.settleQuery,
		service.keepFailedLogQuery,
		service.sanctionedSourceQuery,
		service.sanctionedNetworksQuery,
	); err != nil {
		db.Close()
		return nil, err
	}
	return service, nil
}

func (s *Service) Close() {
	s.keyConfigs.close()
	s.closeFinalizations()
	if done := s.stopRejectionLogs(); done != nil {
		<-done
	}
	if s.db != nil {
		s.db.Close()
	}
}

func (s *Service) Diagnostics() DiagnosticsSnapshot {
	if s == nil {
		return DiagnosticsSnapshot{}
	}
	return DiagnosticsSnapshot{
		KeyConfigCache: s.keyConfigs.diagnostics(),
		RedactionCache: s.keyConfigs.redactionDiagnostics(),
		RejectionLogs:  s.rejectionLogs.snapshot(),
		Database:       s.db.Diagnostics(),
		LocalAdmission: s.localAdmissionDiagnostics(),
		Settlement:     s.settlementDiagnostics(),
		// The monitor compares it with Control's and with its probe key's.
		APIKeyPepperFingerprint: s.apiKeyPepperFingerprint,
	}
}

func (s *Service) parseVerifiedAPIKey(rawAPIKey string) (*APIKeyClaims, string, string, error) {
	if s == nil || !hasSignedAPIKeyShape(rawAPIKey) {
		return nil, "", "", errInvalidAPIKeyShape
	}
	apiKeyHash := hashAPIKey(rawAPIKey, s.apiKeyPepper)
	cacheKey := "api:" + apiKeyHash
	if claims, ok := s.apiKeys.get(cacheKey); ok {
		return claims, apiKeyHash, cacheKey, nil
	}
	claims, err := parseSignedAPIKey(rawAPIKey, s.apiKeyPepper)
	if err != nil {
		return nil, "", cacheKey, err
	}
	claims.admissionKey = cacheKey
	s.apiKeys.put(cacheKey, claims)
	return claims, apiKeyHash, cacheKey, nil
}

func (s *Service) ParseAPIKey(rawAPIKey string) (*APIKeyClaims, error) {
	if s == nil {
		return nil, ErrInvalidAPIKey
	}
	claims, _, _, err := s.parseVerifiedAPIKey(rawAPIKey)
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	now := time.Now()
	if err := s.refusals.get(claims.admissionKey, now); err != nil {
		return claims, err
	}
	if err := s.admitCredential(claims.admissionKey, claims.OrganizationID, now); err != nil {
		return claims, err
	}
	return claims, s.admitOrganization(claims.admissionKey, claims.OrganizationID, now)
}

func (s *Service) ParseDashboardCredential(raw string) (*DashboardCredential, error) {
	if s == nil || s.inferenceTokenPublicKey == nil {
		return nil, ErrInvalidAPIKey
	}
	credential, err := parseDashboardCredential(raw, s.inferenceTokenPublicKey, time.Now())
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	cacheKey := dashboardAdmissionKey(credential)
	now := time.Now()
	if snapshot, ok := s.keyConfigs.get(dashboardConfigCacheKey(credential), now); ok {
		credential.Claims = snapshot.Claims
	}
	if err := s.refusals.get(cacheKey, now); err != nil {
		return credential, err
	}
	organizationID := ""
	if credential.Claims != nil {
		organizationID = credential.Claims.OrganizationID
	}
	return credential, s.admitCredential(cacheKey, organizationID, now)
}

// UsageReservation records quantities once before authorization. Text remains
// in exact UTF-8 bytes; STT presentation divides it by four.
type UsageReservation struct {
	Tokens         int64
	InputTextBytes int64
}

// HoldRequest authorizes one deployment and credential pair. Previous is the
// request's hold when a provider failure moves the request to this pair: one
// statement releases that hold and holds this pair, and a refused move leaves
// the previous hold as it was.
type HoldRequest struct {
	RawAPIKey                string
	Dashboard                *DashboardCredential
	RequestID                string
	ProviderKey              string
	ProductKey               string
	EstimatedUpstreamCostUSD string
	Usage                    UsageReservation
	Snapshot                 *KeyConfigSnapshot
	Prepared                 *PreparedCredential
	ActiveRules              []policy.RuleMatch
	EncryptionKeys           customerkey.Keys
	UpstreamTarget           *UpstreamTarget
	RequestLifetime          time.Duration
	Previous                 *Authorization
	// KeepMemory keeps the request's memory charge after the request ends,
	// until the returned function runs. A close of a hold that the database
	// may have made without answering keeps it.
	KeepMemory func() (release func())
}

// Authorize places the hold that admits a request to its pair's provider. A
// request whose ctx ends while it waits for its organization's statement
// leaves the queue.
func (s *Service) Authorize(ctx context.Context, request HoldRequest) (*Authorization, error) {
	var claims *APIKeyClaims
	apiKeyHash := ""
	if request.Dashboard == nil {
		var err error
		claims, apiKeyHash, _, err = s.parseVerifiedAPIKey(request.RawAPIKey)
		if err != nil {
			return nil, ErrInvalidAPIKey
		}
	}
	return s.authorizeResolvedRequest(ctx, apiKeyHash, claims, request)
}

// PairRefused reports a refusal that another deployment and credential pair
// can pass: its credential is unusable, disabled or expired, or its cost,
// tokens or matched rules reach a limit or the balance.
func PairRefused(err error) bool {
	var refusal *RequestError
	if !errors.As(err, &refusal) {
		return false
	}
	switch refusal {
	case ErrInsufficientBalance, ErrByok, ErrByokRequired, ErrByokTarget, errByokNotAllowed:
		return true
	}
	// Other policy results are limits, except a disabled or expired scope that
	// every pair shares.
	code := refusal.Code
	return policyResultErrors[code] == refusal && (strings.HasPrefix(code, "credential_") ||
		!strings.HasSuffix(code, "_disabled") && !strings.HasSuffix(code, "_expired"))
}

func (s *Service) authorizeResolvedRequest(ctx context.Context, apiKeyHash string, claims *APIKeyClaims, request HoldRequest) (*Authorization, error) {
	dashboard, requestID, providerKey, productKey := request.Dashboard, request.RequestID, request.ProviderKey, request.ProductKey
	snapshot, prepared, encryptionKeys, usage := request.Snapshot, request.Prepared, request.EncryptionKeys, request.Usage
	previous := request.Previous
	// A request keeps one settlement place through every pair it moves to.
	var releaseFinalization func()
	if previous == nil {
		var err error
		releaseFinalization, err = s.reserveFinalization()
		if err != nil {
			return nil, err
		}
		defer func() {
			if releaseFinalization != nil {
				releaseFinalization()
			}
		}()
	}
	if snapshot == nil || snapshot.Config == nil || snapshot.Claims == nil || snapshot.CredentialsGeneration < 1 || snapshot.Versions == nil {
		return nil, ErrGatewayUnavailable
	}
	if prepared == nil || prepared.snapshot != snapshot || prepared.provider != providerKey {
		return nil, ErrByok
	}
	selection := prepared.selection
	// Plugin roots are covered by the checked source revisions. SQL needs only
	// the root identifier for the selected encrypted provider credential.
	credentialKeyID := ""
	if selection.Mode == "encrypted" && selection.Credential != nil {
		credentialKeyID = selection.Credential.EncryptionKeyID
	}
	selectedPolicy, err := snapshot.PolicyForCredential(providerKey, prepared.index, encryptionKeys, time.Now(), nil)
	if err != nil {
		return nil, err
	}
	matchedRules := make([]struct {
		Scope policy.Scope `json:"scope"`
		ID    string       `json:"id"`
		Rule  string       `json:"rule"`
	}, len(request.ActiveRules))
	for i, match := range request.ActiveRules {
		if match.Source < 0 || match.Source >= len(*selectedPolicy.Versions) {
			return nil, ErrGatewayUnavailable
		}
		version := (*selectedPolicy.Versions)[match.Source]
		matchedRules[i].Scope, matchedRules[i].ID, matchedRules[i].Rule = version.Scope, version.ID, match.Name
	}
	selectionJSON, err := json.Marshal(struct {
		Mode string  `json:"mode"`
		ID   *string `json:"byokId"`
	}{selection.Mode, nullableString(selection.ID)})
	if err != nil {
		return nil, ErrGatewayUnavailable
	}
	// Times are whole microseconds, as PostgreSQL stores them, so that a
	// batch and a single authorization receive the same values.
	started := time.Now().Truncate(time.Microsecond)
	expiresAt := requestHoldExpiresAt(started.UTC(), request.RequestLifetime)
	holdID, err := newUUIDV7String()
	if err != nil {
		return nil, fmt.Errorf("generate hold id: %w", err)
	}
	upstreamTargetJSON := ""
	if request.UpstreamTarget != nil {
		encoded, marshalErr := json.Marshal(request.UpstreamTarget)
		if marshalErr != nil {
			return nil, ErrByokTarget
		}
		upstreamTargetJSON = string(encoded)
	}
	holdParamsHash := createHoldParamsHash(providerKey, productKey, upstreamTargetJSON)
	releaseAuthorization := s.authorizations.start()
	defer releaseAuthorization()

	// PostgreSQL creates no hold after this time by its own clock, so a close
	// that finds this time passed cannot miss one.
	authorizeBefore := time.Now().Add(authorizeTimeout).Truncate(time.Microsecond)
	pending := &pendingAuthorization{
		arguments: authorizationArguments{
			RequestID:                requestID,
			HoldID:                   holdID,
			ProviderKey:              providerKey,
			ProductKey:               productKey,
			EstimatedUpstreamCostUSD: request.EstimatedUpstreamCostUSD,
			ExpiresAt:                expiresAt,
			HoldParamsHash:           holdParamsHash,
			EncryptionKeyID:          nullableString(credentialKeyID),
			AuthorizeBefore:          authorizeBefore,
			ReservedTokens:           usage.Tokens,
			ActiveUntil:              expiresAt.Add(-holdSettlementExpiryBuffer + time.Minute),
			CredentialsGeneration:    snapshot.CredentialsGeneration,
			CachedByok:               selectionJSON,
			PolicyVersions:           selectedPolicy.Versions,
			ActiveRules:              matchedRules,
			InputTextBytes:           usage.InputTextBytes,
			NodeID:                   nullableString(s.nodeID),
		},
		admissionKey: callerAdmissionKey(claims, dashboard),
		waitUntil:    authorizeBefore.Add(-authorizeStatementReserve),
		done:         make(chan authorizationOutcome, 1),
	}
	arguments := &pending.arguments
	if upstreamTargetJSON != "" {
		arguments.UpstreamTarget = json.RawMessage(upstreamTargetJSON)
	}
	// SQL finds the key by the ID that the API key's MAC or the dashboard credential names.
	if dashboard != nil {
		arguments.KeyID = &dashboard.KeyID
		arguments.DashboardActorUserID = &dashboard.ActorUserID
		arguments.DashboardSessionID = &dashboard.SessionID
	} else if claims != nil {
		arguments.KeyID = &claims.KeyID
	}
	if apiKeyHash != "" {
		arguments.HashedKey = &apiKeyHash
	}
	if previous != nil {
		pending.previous = &previous.holdID
		pending.alone = true
	}
	waitCtx, cancelWait := context.WithDeadline(ctx, pending.waitUntil)
	outcome := s.authorizeInOrder(waitCtx, snapshot.Claims.OrganizationID, pending)
	cancelWait()
	if outcome.refusal != nil {
		return nil, outcome.refusal
	}
	if outcome.err != nil {
		// A statement that never left the gateway cannot have created a hold, so
		// it needs no close. An exhausted pool or an unreachable database then
		// gets no extra calls from the requests it already failed. A move that
		// may have committed leaves either hold for settlement, which accepts
		// the previous pair's log without usage.
		if outcome.sent && !pgconn.SafeToRetry(outcome.err) && previous == nil {
			release, releasePlace := releaseFinalization, releaseFinalization
			if request.KeepMemory != nil {
				releaseMemory := request.KeepMemory()
				release = func() { releasePlace(); releaseMemory() }
			}
			s.closeUnconfirmedAuthorization(requestID, snapshot.Claims.KeyID, authorizeBefore, release)
			releaseFinalization = nil
		}
		// The caller left before a statement authorized the request, so the
		// database holds nothing for it, and nobody waits for an answer.
		if errors.Is(outcome.err, context.Canceled) {
			return nil, outcome.err
		}
		return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, outcome.err)
	}
	row := outcome.row
	s.organizationRates.learn(snapshot.Claims.OrganizationID, row.RequestsPerSecond)

	if resultErr := authorizationResultError(row.Result, row.WaitMS); resultErr != nil {
		if !row.ConfigCurrent && derefString(row.KeyID) == snapshot.Claims.KeyID {
			s.confirmKeyConfig(apiKeyHash, dashboard, snapshot, false, started)
		}
		return nil, resultErr
	}

	switch row.Result {
	case "ok":
		keyID := derefString(row.KeyID)
		organizationID := derefString(row.OrganizationID)
		userID := derefString(row.UserID)
		grantID := row.GrantID
		if dashboard != nil {
			if keyID != dashboard.KeyID || userID != dashboard.ActorUserID {
				return nil, ErrInvalidAPIKey
			}
		} else {
			if claims == nil ||
				keyID != claims.KeyID ||
				organizationID != claims.OrganizationID ||
				userID != claims.ResponsibleID ||
				!equalOptionalString(grantID, claims.GrantID) {
				return nil, ErrInvalidAPIKey
			}
		}
		upstreamByok := derefString(row.UpstreamByok)
		authorizedBilledCostUSD, amountErr := parseDatabaseMoney(row.AuthorizedBilledCostUSD, "authorized billed cost")
		if amountErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, amountErr)
		}
		taxRate, rateErr := parseTaxRate(row.TaxRate)
		if rateErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, rateErr)
		}
		if (taxRate == 0) != (row.TaxRateID == nil) {
			return nil, fmt.Errorf("%w: database returned a tax rate without its row", ErrGatewayUnavailable)
		}
		authorization := &Authorization{releaseFinalization: releaseFinalization, holdID: holdID, AuthorizedBilledCostUSD: authorizedBilledCostUSD, taxRate: taxRate, taxRateText: *row.TaxRate, taxRateID: row.TaxRateID, CreatedAt: derefTime(row.CreatedAt), GrantID: grantID, KeyID: keyID, OrganizationID: organizationID, ProductKey: productKey, ProviderKey: providerKey, RequestID: requestID, UpstreamByok: upstreamByok, UpstreamTargetJSON: upstreamTargetJSON, UserID: userID}
		if previous != nil {
			authorization.releaseFinalization = previous.releaseFinalization
			authorization.StartAt = previous.StartAt
		} else if row.WaitMS != nil && *row.WaitMS > 0 {
			// The wait starts at this gateway's clock when the result arrives, a
			// little after PostgreSQL's, so the requests start no faster than
			// PostgreSQL spaced them.
			authorization.StartAt = time.Now().Add(time.Duration(*row.WaitMS) * time.Millisecond)
		}
		releaseFinalization = nil // Ownership follows the accepted request through settlement.
		if upstreamByok == "" {
			return authorization, ErrByok
		}
		s.confirmKeyConfig(apiKeyHash, dashboard, snapshot, row.ConfigCurrent, started)
		if selection.Mode == "stored" {
			credential := selection.Credential
			if credential == nil || credential.ID != upstreamByok || credential.OrganizationID != organizationID ||
				credential.Provider != providerKey {
				return authorization, ErrByok
			}
			if providerKey == "azure" {
				bound, parseErr := parseAzureBoundBinding(derefString(row.UpstreamByokBinding))
				if parseErr != nil {
					return authorization, ErrByok
				}
				authorization.AzureBinding = &bound.Binding
			} else if row.UpstreamByokBinding != nil {
				return authorization, ErrByok
			}
			authorization.UpstreamByokSecret = prepared.Secret
		} else if selection.Mode == "encrypted" {
			credential := selection.Credential
			if credential == nil || credential.ID != upstreamByok || row.UpstreamByokBinding != nil || !encryptionKeys.Matches(credential.EncryptionKeyID) {
				return authorization, customerkey.ErrKey
			}
			authorization.UpstreamByokSecret = prepared.Secret

		} else if upstreamByok != ManagedUpstreamByok || row.UpstreamByokBinding != nil {
			return authorization, ErrByok
		}
		return authorization, nil
	default:
		return nil, fmt.Errorf("unknown hold authorization result: %s", row.Result)
	}
}

func authorizationResultError(result string, waitMS *int64) error {
	if refusal := databaseRefusals[result]; refusal != nil {
		if refusal.statusCode == 429 && waitMS != nil {
			// A reset can be up to 1,000 years away, past the longest Duration.
			delay := time.Duration(math.MaxInt64)
			if *waitMS < int64(delay/time.Millisecond) {
				delay = time.Duration(*waitMS) * time.Millisecond
			}
			return &retryAfterError{refusal, delay}
		}
		return refusal
	}
	switch result {
	case "params_mismatch", "authorization_closed", "expired", "hold_not_found":
		// The gateway's own parameters or clock failed these checks, not the caller.
		return fmt.Errorf("%w: authorization %s", ErrGatewayUnavailable, result)
	case "encryption_key_required":
		return customerkey.ErrKey
	case "config_stale":
		return ErrAPIKeyConfigStale
	case "invalid_amount":
		return errors.New("invalid estimated upstream cost")
	default:
		return nil
	}
}

func dashboardAdmissionKey(credential *DashboardCredential) string {
	if credential == nil {
		return ""
	}
	// KeyID is an unsigned database selector and cannot scope local admission.
	return "dashboard:" + credential.ActorUserID + ":" + credential.SessionID
}

func durationOrDefault(value time.Duration, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func requestHoldExpiresAt(now time.Time, requestLifetime time.Duration) time.Time {
	return now.Add(durationOrDefault(requestLifetime, GatewayRequestLifetime) + holdSettlementExpiryBuffer)
}

func ErrorStatus(err error) int {
	var statusError interface{ StatusCode() int }
	if errors.As(err, &statusError) {
		return statusError.StatusCode()
	}
	return 500
}

func newUUIDV7String() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func nullableString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func equalOptionalString(left *string, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func parseDatabaseMoney(value *string, field string) (*money.USD, error) {
	if value == nil {
		return nil, fmt.Errorf("database returned no %s", field)
	}
	parsed, err := ParseUSD(*value)
	if err != nil {
		return nil, fmt.Errorf("database returned an invalid %s: %w", field, err)
	}
	return parsed, nil
}

// taxRateUnits is a tax rate's denominator: numeric(9, 8) stores eight decimal
// places.
const taxRateUnits = 100_000_000

// parseTaxRate reads the rate an admitted hold fixed, which PostgreSQL returns
// without trailing zeros: 0, or a fraction below 1.
func parseTaxRate(value *string) (int64, error) {
	if value == nil {
		return 0, fmt.Errorf("database returned no tax rate")
	}
	if *value == "0" {
		return 0, nil
	}
	digits, ok := strings.CutPrefix(*value, "0.")
	if !ok || digits == "" || len(digits) > 8 || strings.HasSuffix(digits, "0") ||
		strings.Trim(digits, "0123456789") != "" {
		return 0, fmt.Errorf("database returned an invalid tax rate")
	}
	units, err := strconv.ParseInt(digits+strings.Repeat("0", 8-len(digits)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("database returned an invalid tax rate: %w", err)
	}
	return units, nil
}

func derefTime(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}
