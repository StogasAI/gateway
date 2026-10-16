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
	if keyConfig != nil {
		ctx.policyVersions = keyConfig.Versions
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
	var candidateBudget policy.SourceBudget
	bodyCapacity := cap(ctx.body)
	run.finishPreprocessing = s.preprocessing.begin(len(ctx.body))
	first, err := catalog.ResolveRequest(catalog.RequestInput{
		Body:                 ctx.body,
		Fields:               fields,
		Method:               ctx.request.Method,
		Path:                 ctx.request.URL.Path,
		Policy:               keyConfig.Config,
		AvailableCredentials: keyConfig.AvailableCredentials(credential.EncryptionKeys),
		DeploymentEligible:   stogas.CredentialDeploymentFilter(keyConfig, startedAt),
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
		CheckCandidate: func(provider schemas.ModelProvider, index int, _ catalog.Deployment) error {
			candidate, err := s.runtime.Billing().PrepareCredential(keyConfig, string(provider), index, credential.EncryptionKeys)
			if err == nil {
				err = stogas.ValidatePreparedCredential(candidate, provider)
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
	if err == nil {
		err = run.accountPolicyMemory()
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
	// The receipt commits to the received bytes, which the run releases with
	// its plan.
	if wantsMetadata(run.request) {
		if _, err := ctx.receiptRequestDigest(); err != nil {
			run.finishPreprocessing()
			run.cancel()
			run.releasePlan()
			s.writeProofError(ctx)
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
