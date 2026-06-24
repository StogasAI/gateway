package catalog

#Id:               string & =~"^[a-z0-9][a-z0-9._:-]*$"
#Slug:             string & =~"^[a-z0-9][a-z0-9._:/+-]*$"
#Header:           string & =~"^[a-z0-9][a-z0-9-]*$"
#Date:             string & =~"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
#EndpointTemplate: string & =~"^https://"
#Path:             string & =~"^/"
#AtomUSD:          string & =~"^[0-9]+$"
#ClaimText:        "unknown" | string
#ClaimBool:        "unknown" | bool
#MaybeDate:        null | #Date
#MaybeString:      null | string
#SlugAttributeRef: "authorSlugs" | "providerSlugs" | "modelSlugs"

#Modality:      "text" | "image" | "audio" | "video"
#Flavor:        "base" | "instruct" | "search" | "preview" | "code" | "unknown"
#Quantization:  "fp32" | "bf16" | "fp16" | "fp8" | "fp6" | "fp4" | "int8" | "int4" | "unknown"
#TeeStatus:        "attested" | "provider_claimed" | "unverified_label" | "unknown"
#TeeMechanism:     "sev-snp" | "tdx" | "nitro-enclave" | "unknown"
#ProviderEndpointClass: "responses" | "chat_completion" | "messages" | "image_edit" | "ocr" | "rerank"
#SupportStatus:    "supported" | "unsupported" | "unknown"
#LocationKind:     "world" | "multi_region" | "continent" | "macro_region" | "economic_region" | "country" | "state" | "city" | "datacenter_region"
#ServiceTier: "auto" | "default" | "standard" | "standard_only" | "flex" | "priority"

#OpenAPIValue: null | bool | number | string | [...#OpenAPIValue] | {
	[string]: #OpenAPIValue
}

#ModelSlugsPatch: close({
	value?:                                   #Slugs
	expandAttributeWithEnumeratedSuffixes?:   [...#Slug]
})

#StogasEndpoint: close({
	path:   #Path
	method: "post" | "POST"
})

#Location: close({
	name:     string
	kind:     #LocationKind
	parentId: #Id | null
	isoCode?: string
	domainPrefix?: string
})
