package catalog

#ProviderEndpoint: close({
	providerId:                #Id
	stogasEndpointId:          #Id
	endpoint:                  #EndpointTemplate
	regionId:                  #Id
	regionalStorageClaimed:    #ClaimBool
	regionalProcessingClaimed: #ClaimBool
	fallbackBehavior:          string
	e2ee:                      #ClaimText
	gdpr:                      #ClaimText
	class:                     #ProviderEndpointClass
	policyProfiles?:           [...#PolicyProfileId]
	pricing?:                  #ProviderPricing
	schema?:                   #SchemaPatch
})
