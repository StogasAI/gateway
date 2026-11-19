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

// neededRoots returns the distinct roots that pairs need, sorted. The log lists
// the roots that a request needs or lacks, so pairs that need more than
// customerkey.MaxRequestKeys fail the request.
func neededRoots(keyConfig *billing.KeyConfigSnapshot, pairs []catalog.PlannedPair) ([]string, error) {
	var ids []string
	for _, pair := range pairs {
		ids = append(ids, keyConfig.RequiredRoots(string(pair.Provider), pair.Credential, pair.Policy)...)
	}
	ids = customerkey.SortedIDs(ids)
	if len(ids) > customerkey.MaxRequestKeys {
		return nil, billing.ErrRequestKeys
	}
	return ids, nil
}

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
	// A refusal before the plan resolves logs the type that the body asks for.
	ctx.requestType = requestTypeOf(ctx.request.URL.Path, fields)
	credential.EncryptionKeys, err = takeEncryptionKeys(fields)
	if err != nil {
		s.writeBillingError(ctx, err)
		return nil
	}
	keyConfig, err := s.keyConfigForCredential(credential)
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
	if keyConfig.Config.DeniedAt(startedAt.UTC()) {
		run.releasePlan()
		s.writeCatalogError(ctx, catalog.ErrScheduleDenied)
		return nil
	}
	client := s.client(ctx)
	if refusal := keyConfig.Config.ClientRefusal(client); refusal != policy.Admitted {
		run.releasePlan()
		s.writeCatalogError(ctx, catalog.ClientDenied(client, refusal))
		return nil
	}
	transport := ctx.transport()
	if keyConfig.Config.TransportDenied(transport) {
		run.releasePlan()
		s.writeCatalogError(ctx, catalog.TransportDenied(transport))
		return nil
	}
	// The plan's root check covers every pair the request may try, so its
	// roots are the ones the request needs.
	var roots []string
	bodyCapacity := cap(ctx.body)
	run.finishPreprocessing = s.preprocessing.begin(len(ctx.body))
	first, err := catalog.ResolveRequest(catalog.RequestInput{
		Body:                 ctx.body,
		Fields:               fields,
		Method:               ctx.request.Method,
		Path:                 ctx.request.URL.Path,
		Client:               client,
		Transport:            transport,
		Policy:               keyConfig.Config,
		AvailableCredentials: keyConfig.AvailableCredentials(),
		DeploymentEligible:   stogas.CredentialDeploymentFilter(keyConfig, startedAt),
		CredentialKind: func(provider schemas.ModelProvider, index int) string {
			return keyConfig.CredentialKind(string(provider), index)
		},
		CredentialOptions: func(provider schemas.ModelProvider, index int) []billing.HeldOption {
			return keyConfig.AccountOptions(string(provider), index)
		},
		LoadRedactionPolicy: keyConfig.RedactionPolicy,
		ReserveBody: func(bytes int) error {
			if !lease.resize(max(bodyCapacity, bytes)) {
				return errRequestMemoryCapacity
			}
			return nil
		},
		CompileRequestPolicy: func(raw []byte) (*policy.Request, error) {
			return policy.CompileRequest(raw, keyConfig.Claims.OrganizationID, credential.EncryptionKeys)
		},
		CheckRoots: func(pairs []catalog.PlannedPair, plan bool) error {
			ids, err := neededRoots(keyConfig, pairs)
			if err == nil {
				if plan {
					roots = ids
				}
				err = credential.EncryptionKeys.Missing(keyConfig.EncryptionKeys, ids...)
			}
			if err != nil {
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
		PairWaits: func(provider schemas.ModelProvider, index int, deployment catalog.Deployment) error {
			if key, ok := pairWaitKey(keyConfig, provider, index, deployment.ID); ok {
				return s.pairWaits.refusal(key)
			}
			return nil
		},
		// The run ranks a pair that the plan refused like a failed call, and
		// the plan, when it refuses every pair, keeps the one the run would.
		PairSkipped: func(err error) { run.noteLocal(err, -1) },
		Prefers: func(err, kept error) bool {
			return localFailure(err, -1).replaces(localFailure(kept, -1))
		},
		CredentialPolicy: func(provider schemas.ModelProvider, index int) (catalog.RequestPolicy, error) {
			selected, err := keyConfig.PolicyForCredential(string(provider), index, credential.EncryptionKeys, startedAt)
			if err != nil {
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
	if err == nil {
		err = run.accountPolicyMemory()
	}
	// The log names the roots that the plan needs, also when the request
	// fails after planning. Planning that fails earlier names none, and a
	// request refused for missing roots names those.
	ctx.encryptionKeyIDs = roots
	if missing := (*customerkey.MissingError)(nil); errors.As(err, &missing) {
		ctx.encryptionKeyIDs = missing.IDs
	}
	if err != nil {
		run.finishPreprocessing()
		run.plan = first
		run.releasePlan()
		if errors.Is(err, errRequestMemoryCapacity) {
			s.writeRequestMemoryCapacity(ctx)
			return nil
		}
		s.writeCatalogError(ctx, err)
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

func (s *Server) keyConfigForCredential(credential apiCredential) (*billing.KeyConfigSnapshot, error) {
	if s == nil || s.runtime == nil || s.runtime.Billing() == nil {
		return nil, billing.ErrGatewayUnavailable
	}
	if credential.Dashboard != nil {
		return s.runtime.Billing().ConfigForDashboard(context.Background(), credential.Dashboard, credential.EncryptionKeys)
	}
	return s.runtime.Billing().ConfigForAPIKey(context.Background(), credential.Raw, credential.Claims, credential.EncryptionKeys)
}
