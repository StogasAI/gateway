package catalog

import "list"

let sourceStogas = stogas
let sourceStogasEndpoints = stogasEndpoints
let sourceLocations = locations
let sourceAuthors = authors
let sourceModels = models
let sourceProviders = providers
let sourceProviderEndpoints = providerEndpoints
let sourceDeployments = deployments

compiled: {
	_checks: #Catalog
	graph: {
		stogas:      sourceStogas
		stogasEndpoints: sourceStogasEndpoints
		locations:   sourceLocations
		authors:     sourceAuthors
		models:      sourceModels
		providers:   sourceProviders
		providerEndpoints: sourceProviderEndpoints
		deployments: sourceDeployments
	}
	indexes: {
		author_slugs: {
			for id, author in sourceAuthors {
				for slug in author.authorSlugs {
					(slug): id
				}
			}
		}
		provider_slugs: {
			for id, provider in sourceProviders {
				for slug in provider.providerSlugs {
					(slug): id
				}
			}
		}
		provider_endpoint_request_slugs: {
		}
		provider_endpoint_deployments: {
		}
		stogas_endpoint_provider_endpoints: {
			for stogasEndpointId, _ in sourceStogasEndpoints {
				(stogasEndpointId): [
					for endpointId, endpoint in sourceProviderEndpoints
					if list.Contains(endpoint.stogasEndpoints, stogasEndpointId) {endpointId},
				]
			}
		}
	}
}
