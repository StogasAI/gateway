package catalog

#Provider: close({
	name:       string
	providerSlugs: #Slugs
	cancellationSupported:               #ClaimBool
	streamingSupported:                  #ClaimBool
	streamCancellationSupported:         #ClaimBool
	functionCallingSupported:            #ClaimBool
	promptCachingSupported:              #ClaimBool
	systemMessagesSupported:             #ClaimBool
	toolChoiceSupported:                 #ClaimBool
	webSearchSupported:                  #ClaimBool
	countTokensEndpoints:                [...#Id]
	moderated:                           bool
	usesPseudoanonymousUserId:           bool
	dataRetentionDaysClaimed:            int & >=0
	dataStorageRegionPinnedByDefaultClaimed: #ClaimBool
	dataUsedForTrainingClaimed:          #ClaimBool
	dataSoldClaimed:                     #ClaimBool
	dataSharedForCrossContextBehavioralAdsClaimed: #ClaimBool
	headquarteredLocationId:             #Id
	datacenterLocationIds:               [...#Id]
	pricing?:                            #ProviderPricing
})
