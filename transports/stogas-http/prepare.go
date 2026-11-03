package stogashttp

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/billing"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// startRun resolves the request's pairs and binds the first one that
// prepares. It returns nil after it has written the response.
func (s *Server) startRun(ctx *requestContext, startedAt time.Time, preparation *requestMemoryLease) *providerRun {
	lease := ctx.memory
	credential, ok := s.requireInferenceEnvelope(ctx)
	if !ok {
		return nil
	}
	ctx.credential = nil
	decodeStarted := time.Now()
	s.jsonDecode.start()
	fields, err := catalog.DecodeRequestBody(ctx.body, lease.admitJSON)
	s.jsonDecode.finish(time.Since(decodeStarted), uint64(len(ctx.body)))
	if err != nil {
		if errors.Is(err, errRequestMemoryCapacity) {
			s.writeRequestMemoryCapacity(ctx)
			return nil
		}
		s.writeCatalogError(ctx, err)
		return nil
	}
	credential.EncryptionKeys, err = takeEncryptionKeys(fields)
	if err != nil {
		s.writeBillingError(ctx, err)
		return nil
	}
	keyConfig, err := s.keyConfigForCredential(credential)
	// Cached settings that refuse the request's encryption keys may predate a key that the
	// organization registered since, so the request asks as a routing refusal does.
	if err != nil && keyConfig != nil && keyConfig.Config != nil && errors.Is(err, customerkey.ErrKey) {
		if fresh, freshErr := s.refreshRefusedKeyConfig(credential, keyConfig); fresh != nil || freshErr != nil {
			keyConfig, err = fresh, freshErr
		}
	}
	if keyConfig != nil {
		ctx.policyVersions = keyConfig.Logged
		if credential.Dashboard != nil && keyConfig.Claims != nil {
			ctx.claims = keyConfig.Claims
		}
	}
	if err != nil {
		credential.EncryptionKeys.Clear()
		s.writeBillingError(ctx, err)
		return nil
	}
	run := &providerRun{
		server: s, client: ctx, credential: credential, keyConfig: keyConfig,
		policyMemory: s.memory.newLease(requestLifetimeMemory), preparation: preparation,
		bodyBytes: len(ctx.body), startedAt: startedAt,
	}
	if err := run.accountPolicyMemory(); err != nil {
		run.releasePlan()
		s.writeRequestMemoryCapacity(ctx)
		return nil
	}
	var candidateBudget policy.SourceBudget
	bodyCapacity := cap(ctx.body)
	run.finishPreprocessing = s.preprocessing.begin(len(ctx.body))
	// The closures read keyConfig when routing calls them, so a second pass reads its new value.
	resolve := func() (*catalog.ResolvedRequest, error) {
		if keyConfig.Config.DeniedAt(startedAt.UTC()) {
			return nil, catalog.ErrScheduleDenied
		}
		return catalog.ResolveRequest(catalog.RequestInput{
			Body:                 ctx.body,
			Fields:               fields,
			Method:               ctx.request.Method,
			Path:                 ctx.request.URL.Path,
			Policy:               keyConfig.Config,
			AvailableCredentials: keyConfig.AvailableCredentials(),
			DeploymentEligible:   stogas.CredentialDeploymentFilter(keyConfig, startedAt),
			DeploymentChanged:    stogas.CredentialTargetChanged(keyConfig),
			LoadRedactionPolicy:  keyConfig.RedactionPolicy,
			ReserveBody: func(bytes int) error {
				if !lease.resize(max(bodyCapacity, bytes)) {
					return errRequestMemoryCapacity
				}
				return nil
			},
			CompileRequestPolicy: func(raw []byte) (*policy.Request, error) {
				return policy.CompileRequest(raw, keyConfig.Claims.OrganizationID, credential.EncryptionKeys)
			},
			CheckRoots: func(pairs []catalog.PlannedPair) error {
				var ids []string
				for _, pair := range pairs {
					ids = append(ids, keyConfig.RequiredRoots(string(pair.Provider), pair.Credential, pair.Policy)...)
				}
				if err := credential.EncryptionKeys.Missing(keyConfig.Config.EncryptionKeys, ids...); err != nil {
					public := stogas.PublicBillingErrorFor(err)
					return errors.Join(err, catalog.APIError{Code: public.Code, StatusCode: public.StatusCode, Type: public.Type, Message: public.Message})
				}
				return nil
			},
			CheckCandidate: func(provider schemas.ModelProvider, index int, deployment catalog.Deployment) error {
				candidate, err := s.runtime.Billing().PrepareCredential(keyConfig, string(provider), index, credential.EncryptionKeys)
				if err == nil {
					err = stogas.ValidatePreparedCredential(candidate, provider, deployment)
				}
				if err != nil {
					candidate.Clear()
					public := stogas.PublicBillingErrorFor(err)
					return errors.Join(err, catalog.APIError{Code: public.Code, StatusCode: public.StatusCode, Type: public.Type, Message: public.Message})
				}
				run.prepared.Clear()
				run.prepared = candidate
				return nil
			},
			CredentialPolicy: func(provider schemas.ModelProvider, index int) (catalog.RequestPolicy, error) {
				selected, err := keyConfig.PolicyForCredential(string(provider), index, credential.EncryptionKeys, startedAt, &candidateBudget)
				if err != nil {
					if errors.Is(err, policy.ErrSourceBudget) {
						return catalog.RequestPolicy{}, err
					}
					public := stogas.PublicBillingErrorFor(err)
					return catalog.RequestPolicy{}, errors.Join(err, catalog.APIError{Code: public.Code, StatusCode: public.StatusCode, Type: public.Type, Message: public.Message})
				}
				return catalog.RequestPolicy{Config: selected.Config, LoadActivePlugins: func(config *policy.Config) (*policy.ActivePlugins, error) {
					compiled, err := keyConfig.ActivePlugins(config, credential.EncryptionKeys)
					if err != nil {
						public := stogas.PublicBillingErrorFor(err)
						return nil, errors.Join(err, catalog.APIError{Code: public.Code, StatusCode: public.StatusCode, Type: public.Type, Message: public.Message})
					}
					return compiled, nil
				}}, nil
			},
		})
	}
	first, err := resolve()
	// Routing refuses from the cached configuration before any hold could find it stale, so a
	// credential just assigned, a target that a check found or a member chose, or a policy that
	// now allows the request would otherwise serve only once the snapshot expired. A configuration
	// that changed since routes the request again.
	refusedBySettings := false
	if err != nil && refusedByConfiguration(err) {
		if fresh, freshErr := s.refreshRefusedKeyConfig(credential, keyConfig); fresh != nil || freshErr != nil {
			first.ReleasePlan()
			first = nil
			// The first pass prepared its candidates from the old snapshot, which no hold accepts.
			run.prepared.Clear()
			run.prepared = nil
			if fresh != nil {
				ctx.policyVersions = fresh.Logged
				if credential.Dashboard != nil && fresh.Claims != nil {
					ctx.claims = fresh.Claims
				}
			}
			// The current settings refuse the request as they would refuse a new one.
			if err, refusedBySettings = freshErr, freshErr != nil; err == nil {
				keyConfig, run.keyConfig, candidateBudget = fresh, fresh, policy.SourceBudget{}
				if err = run.accountPolicyMemory(); err == nil {
					// Routing removed fields such as the request's own policy from the first pass's
					// map, so the second pass reads the unchanged body again.
					if fields, err = catalog.DecodeRequestBody(ctx.body, nil); err == nil {
						first, err = resolve()
					}
				}
			}
		}
	}
	if err == nil {
		err = run.accountPolicyMemory()
	}
	if err != nil {
		run.finishPreprocessing()
		run.plan = first
		run.releasePlan()
		switch {
		case errors.Is(err, errRequestMemoryCapacity):
			s.writeRequestMemoryCapacity(ctx)
		case refusedBySettings:
			s.writeBillingError(ctx, err)
		default:
			s.writeCatalogError(ctx, err)
		}
		return nil
	}
	ctx.requestType = string(first.RequestType)
	run.plan = first
	nodeID := ""
	if s.secure != nil {
		nodeID = s.secure.NodeID()
	}
	run.request, run.state, run.cancel, err = newRequestContext(ctx, startedAt, first, credential, nodeID)
	if err != nil {
		run.finishPreprocessing()
		run.releasePlan()
		if errors.Is(err, context.DeadlineExceeded) {
			s.writeBillingError(ctx, err)
			return nil
		}
		s.writeError(ctx, http.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": err.Error(), "type": "invalid_request_error"},
		})
		return nil
	}
	// The receipt commits to the received request, which the run releases
	// with its plan.
	if wantsMetadata(run.request) {
		if _, err := ctx.receiptRequestDigest(); err != nil {
			run.finishPreprocessing()
			run.cancel()
			run.releasePlan()
			if refusal, ok := receiptContentError(err); ok {
				s.writeCatalogError(ctx, refusal)
			} else {
				s.writeProofError(ctx)
			}
			return nil
		}
	}
	if !run.bindFrom(first) {
		s.failRun(ctx, run, true)
		return nil
	}
	return run
}

// refusedByConfiguration reports a refusal of the request itself, which the key's policies,
// credentials or Azure targets may decide and a cached configuration can make out of date.
// Refusals that no configuration decides, such as malformed JSON, ask too: they cost at most the
// one check a second that every refused request of the key shares.
func refusedByConfiguration(err error) bool {
	var refusal catalog.APIError
	return errors.As(err, &refusal) &&
		(refusal.StatusCode == http.StatusBadRequest || refusal.StatusCode == http.StatusForbidden)
}

// refreshRefusedKeyConfig returns the settings to route a refused request by again, or the error
// that the current settings answer it with, or neither to keep the refusal.
func (s *Server) refreshRefusedKeyConfig(credential apiCredential, stale *billing.KeyConfigSnapshot) (*billing.KeyConfigSnapshot, error) {
	if s == nil || s.runtime == nil || s.runtime.Billing() == nil {
		return nil, nil
	}
	return s.runtime.Billing().RefreshRefusedConfig(
		context.Background(), credential.Raw, credential.Claims, credential.Dashboard, credential.EncryptionKeys, stale,
	)
}

func (s *Server) keyConfigForCredential(credential apiCredential) (*billing.KeyConfigSnapshot, error) {
	if s == nil || s.runtime == nil || s.runtime.Billing() == nil {
		return nil, billing.ErrGatewayUnavailable
	}
	if credential.Dashboard != nil {
		return s.runtime.Billing().ConfigForDashboard(context.Background(), credential.Dashboard, credential.EncryptionKeys)
	}
	return s.runtime.Billing().ConfigForAPIKey(context.Background(), credential.Raw, credential.Claims, credential.EncryptionKeys)
}
