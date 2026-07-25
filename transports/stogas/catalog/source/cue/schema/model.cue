package catalog

#Model: close({
	authorId:      #Id
	name:          string
	family:        string
	series:        string
	snapshot:      #MaybeDate
	flavors:       [...#Flavor]
	// Exact controls shown to clients. Bifrost owns normal provider conversion;
	// overrides are only for model exceptions the provider adapter does not own.
	reasoningEfforts: [...#ReasoningEffort]
	reasoningEffortOverrides?: {
		[#ReasoningEffort]: #ReasoningEffort
	}
	contextWindowTokens: int & >=0
	maxOutputTokens:     int & >=0
	inputModalities:     [...#Modality]
	outputModalities:    [...#Modality]
	releaseDate:     #MaybeDate
	knowledgeCutoff: #MaybeDate
})
