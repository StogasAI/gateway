package catalog

#Author: close({
	description: string
	region: close({
		locationId: #Id
		claim:      #ClaimText
	})
	authorSlugs: #Slugs
	name:       string
})
