package catalog

stogas:      #Stogas
stogasEndpoints: [#Id]: #StogasEndpoint
locations:   close({nodes: [#Id]: #Location})
authors:     [#Id]: #Author
models:      [#Id]: #Model
providers:   [#Id]: #Provider
providerEndpoints: [#Id]: #ProviderEndpoint
deployments: [#Id]: #Deployment

#Catalog: {
	_modelAuthorRefs: {
		for id, model in models {
			(id): authors[model.authorId]
		}
	}

	_authorRegionRefs: {
		for id, author in authors {
			(id): locations.nodes[author.region.locationId]
		}
	}

	_providerLocationRefs: {
		for id, provider in providers {
			"\(id):headquarters": locations.nodes[provider.headquarteredLocationId]
			for location in provider.datacenterLocationIds {
				"\(id):datacenter:\(location)": locations.nodes[location]
			}
		}
	}

	_providerEndpointRefs: {
		for id, endpoint in providerEndpoints {
			for stogasEndpointId in endpoint.stogasEndpoints {
				"\(id):stogasEndpoint:\(stogasEndpointId)": stogasEndpoints[stogasEndpointId]
			}
			"\(id):provider": providers[endpoint.providerId]
			"\(id):region": locations.nodes[endpoint.regionId]
		}
	}

	_deploymentRefs: {
		for id, deployment in deployments {
			"\(id):provider": providers[deployment.providerId]
			"\(id):model": models[deployment.modelId]
			for endpointId in deployment.parentProviderEndpointNodes {
				"\(id):providerEndpoint:\(endpointId)": providerEndpoints[endpointId]
				"\(id):providerEndpoint-provider:\(endpointId)": deployment.providerId & providerEndpoints[endpointId].providerId
			}
		}
	}

	_modelSlugUniqueness: {
		for id, model in models {
			for slug in model.modelSlugs {
				(slug): id
			}
		}
	}

	_providerSlugUniqueness: {
		for id, provider in providers {
			for slug in provider.providerSlugs {
				(slug): id
			}
		}
	}
}
