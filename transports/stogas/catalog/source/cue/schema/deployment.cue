package catalog

#Deployment: close({
	aliasSlugs:          #Slugs
	upstreamModelSlug:   #Slug
	providerId:          #Id
	parentProviderEndpointNodes: [#Id, ...#Id]
	modelId:             #Id
	serviceTier:         #ServiceTier
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
	pricing: #DeploymentPricing
})
