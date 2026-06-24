package catalog

#ProviderEndpoint: close({
	providerId:                #Id
	stogasEndpoints:           [#Id, ...#Id]
	endpoint:                  #EndpointTemplate
	regionId:                  #Id
	regionalStorageClaimed:    #ClaimBool
	regionalProcessingClaimed: #ClaimBool
	fallbackBehavior:          string
	e2ee:                      #ClaimText
	gdpr:                      #ClaimText
	class:                     #ProviderEndpointClass
	pricing?:                  #ProviderPricing
})
