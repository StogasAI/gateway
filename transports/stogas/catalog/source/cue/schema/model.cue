package catalog

#Model: close({
	authorId:      #Id
	name:          string
	family:        string
	series:        string
	snapshot:      #MaybeDate
	flavors:       [...#Flavor]
	reasoning?: #ClaimBool
	contextWindowTokens: int & >=0
	maxOutputTokens:     int & >=0
	inputModalities:     [...#Modality]
	outputModalities:    [...#Modality]
	releaseDate:     #MaybeDate
	knowledgeCutoff: #MaybeDate
})
