package catalog

#Deployment: close({
	modelSlugs?:         #ModelSlugsPatch
	concreteSlugs:       #ConcreteSlugs
	providerId:          #Id
	parentProviderEndpointNodes: [#Id, ...#Id]
	modelId:             #Id
	serviceTier:         #OpenAIServiceTier
	tee?: close({
		status:                #TeeStatus
		mechanism:             #TeeMechanism
		evidenceUri?:          #EndpointTemplate
		attestationStatusUri?: #EndpointTemplate
	})
	streaming?:           #SupportStatus
	streamCancellation?:  #SupportStatus
	tokenizer?:           #ClaimText
	contextWindowTokens?: int & >=0
	maxOutputTokens?:     int & >=0
	policyProfiles?:      [...#PolicyProfileId]
	schema?:              #SchemaPatch
	pricing: #DeploymentPricing
})
