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
#JsonScalar:       null | bool | number | string
#SchemaType:       "array" | "boolean" | "integer" | "number" | "object" | "string" | "null"
#CapabilitySource: "model.reasoning" | "deployment.reasoning"
#SchemaFieldRef: string & =~"^schema\\.(headers|parameters)\\.[a-zA-Z0-9_.-]+$"
#SlugAttributeRef: "authorSlugs" | "providerSlugs" | "modelSlugs"
#PolicyProfileId: string & =~"^[a-z0-9][a-z0-9._:-]*$"

#Modality:      "text" | "image" | "audio" | "video"
#Flavor:        "base" | "instruct" | "search" | "preview" | "code" | "unknown"
#Quantization:  "fp32" | "bf16" | "fp16" | "fp8" | "fp6" | "fp4" | "int8" | "int4" | "unknown"
#TeeStatus:        "attested" | "provider_claimed" | "unverified_label" | "unknown"
#TeeMechanism:     "sev-snp" | "tdx" | "nitro-enclave" | "unknown"
#ProviderEndpointClass: "responses" | "chat_completion" | "image_edit" | "ocr" | "rerank"
#SupportStatus:    "supported" | "unsupported" | "unknown"
#LocationKind:     "world" | "multi_region" | "continent" | "macro_region" | "economic_region" | "country" | "state" | "city" | "datacenter_region"
#OpenAIServiceTier: "default" | "flex" | "priority"

#ParameterSchema: close({
	description?:          string
	type?:                 #SchemaType | [...#SchemaType]
	const?:                #JsonScalar
	enum?:                 [...#JsonScalar]
	required?:             [...string]
	properties?:           [string]: #ParameterSchema
	additionalProperties?: bool | #ParameterSchema
	items?:                #ParameterSchema
	oneOf?:                [...#ParameterSchema]
	anyOf?:                [...#ParameterSchema]
	allOf?:                [...#ParameterSchema]
	minimum?:              number
	maximum?:              number
	minLength?:            int & >=0
	maxLength?:            int & >=0
	minItems?:             int & >=0
	maxItems?:             int & >=0
})

#OpenAPIValue: null | bool | number | string | [...#OpenAPIValue] | {
	[string]: #OpenAPIValue
}

#RejectRule: close({
	path:          string
	values?:       [...#JsonScalar]
	prefixes?:     [...string]
	valuesExcept?: [...#JsonScalar]
	exists?:       bool
	missing?:      bool
	allowedKeys?:  [...string]
	requiredKeys?: [...string]
})

#ModelSlugsPatch: close({
	value?:                                   #Slugs
	expandAttributeWithEnumeratedSuffixes?:   [...#Slug]
})

#ConcreteSlugs: close({
	value?:                                   #Slugs
	expandAttributeWithEnumeratedPrefixes:    [...[...#SlugAttributeRef]]
})

#FieldPolicy: close({
	required:           bool
	type:               #SchemaType | "union"
	values?:            [...string]
	min?:               number
	max?:               number
	schema?:            #ParameterSchema
	overrideAttribute?: true
	deleteAttribute?:   true
	alias?:             #SchemaFieldRef
	implyValue?:        #JsonScalar
	rejectConflict?:    true
	rejectUnsupported?: #CapabilitySource
	reject?:            [...#RejectRule]
})

#FieldPolicyPatch: close({
	required?:          bool
	type?:              #SchemaType | "union"
	values?:            [...string]
	min?:               number
	max?:               number
	schema?:            #ParameterSchema
	overrideAttribute?: true
	deleteAttribute?:   true
	alias?:             #SchemaFieldRef
	implyValue?:        #JsonScalar
	rejectConflict?:    true
	rejectUnsupported?: #CapabilitySource
	reject?:            [...#RejectRule]
})

#SchemaFieldPolicyPatch: close({
	required?:          bool
	type?:              #SchemaType | "union"
	values?:            [...string]
	min?:               number
	max?:               number
	schema?:            #ParameterSchema
	overrideAttribute?: true
	deleteAttribute?:   true
	alias?:             #SchemaFieldRef
	implyValue?:        #JsonScalar
	rejectConflict?:    true
	rejectUnsupported?: #CapabilitySource
	reject?:            [...#RejectRule]
})

#HeaderPolicy: close({
	required:           bool
	type:               "string"
	values?:            [...string]
	schema?:            #ParameterSchema
	overrideAttribute?: true
	deleteAttribute?:   true
	alias?:             #SchemaFieldRef
	implyValue?:        #JsonScalar
	rejectConflict?:    true
	rejectUnsupported?: #CapabilitySource
	reject?:            [...#RejectRule]
})

#SchemaPatch: close({
	parameters?: [string]: #SchemaFieldPolicyPatch
})

#StogasEndpoint: close({
	schema: #StogasEndpointSchema
})

#StogasEndpointSchema: close({
	path:       #Path
	method:     "post" | "POST"
	parameters: [string]: #FieldPolicy
	headers?:   [#Header]: #HeaderPolicy
})

#Location: close({
	name:     string
	kind:     #LocationKind
	parentId: #Id | null
	isoCode?: string
	domainPrefix?: string
})
