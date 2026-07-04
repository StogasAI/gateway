import type {
	Catalog,
	CatalogFlow,
	CatalogGraph,
	GraphChain,
	GraphNodeData,
	LineageNode,
	NodeType
} from './types';
import { MarkerType, type Edge, type Node } from '@xyflow/svelte';

const deploymentOrder = ['gpt-5.5', 'gpt-5.5-flex', 'gpt-5.5-priority'];
const graphChainNodeOrder: NodeType[] = [
	'author',
	'model',
	'deployment',
	'providerEndpoint',
	'provider',
	'stogasEndpoint'
];

export function nodeKey(type: NodeType, id: string) {
	return `${type}:${id}`;
}

export function parseNodeKey(key: string): { type: NodeType; id: string } | null {
	const [type, ...rest] = key.split(':');
	if (!rest.length || !isNodeType(type)) return null;
	return { type, id: rest.join(':') };
}

function isNodeType(value: string): value is NodeType {
	return [
		'stogasEndpoint',
		'author',
		'model',
		'provider',
		'providerEndpoint',
		'deployment',
		'location'
	].includes(value);
}

export function buildFlow(graph: CatalogGraph): CatalogFlow {
	const positions = groupedLayoutPositions(graph);
	const nodes: Node<GraphNodeData>[] = [
		...Object.keys(graph.authors).map((id) =>
			makeNode('author', id, positions.get(nodeKey('author', id)) ?? fallbackNodePosition('author'), {
				rightOut: true
			})
		),
		...Object.keys(graph.models).map((id) =>
			makeNode(
				'model',
				id,
				positions.get(nodeKey('model', id)) ?? fallbackNodePosition('model'),
				{
					leftIn: true,
					rightOut: true
				},
				nodeDetailsForModel(graph, id)
			)
		),
		...Object.keys(graph.providers).map((id) =>
			makeNode(
				'provider',
				id,
				positions.get(nodeKey('provider', id)) ?? fallbackNodePosition('provider'),
				{
					leftOut: true,
					rightIn: true
				}
			)
		),
		...sortedProviderEndpoints(graph).map(([id]) =>
			makeNode(
				'providerEndpoint',
				id,
				positions.get(nodeKey('providerEndpoint', id)) ?? fallbackNodePosition('providerEndpoint'),
				{
					leftOut: true,
					rightIn: true
				}
			)
		),
		...sortedDeployments(graph).map(([id]) =>
			makeNode(
				'deployment',
				id,
				positions.get(nodeKey('deployment', id)) ?? fallbackNodePosition('deployment'),
				{
					leftIn: true,
					rightIn: true
				},
				nodeDetailsForDeployment(graph, id)
			)
		),
		...sortedStogasEndpoints(graph).map(([id]) =>
			makeNode(
				'stogasEndpoint',
				id,
				positions.get(nodeKey('stogasEndpoint', id)) ?? fallbackNodePosition('stogasEndpoint')
			)
		)
	];
	const edges: Edge[] = [];

	for (const [id, model] of Object.entries(graph.models)) {
		edges.push(edge('author', String(model.authorId), 'model', id, 'owns', 'right-out', 'left-in'));
	}
	for (const [id, route] of Object.entries(graph.providerEndpoints)) {
		edges.push(
			edge(
				'provider',
				String(route.providerId),
				'providerEndpoint',
				id,
				'provides',
				'left-out',
				'right-in'
			)
		);
	}
	for (const [id, deployment] of Object.entries(graph.deployments)) {
		edges.push(
			edge(
				'model',
				String(deployment.modelId),
				'deployment',
				id,
				'implements',
				'right-out',
				'left-in'
			)
		);
		edges.push(
			edge(
				'providerEndpoint',
				firstProviderEndpointForDeployment(graph, id),
				'deployment',
				id,
				'serves',
				'left-out',
				'right-in'
			)
		);
	}

	return { nodes, edges };
}

function sortedProviderEndpoints(graph: CatalogGraph) {
	return Object.entries(graph.providerEndpoints).sort(([, a], [, b]) => {
		return String(a.class).localeCompare(String(b.class));
	});
}

function sortedStogasEndpoints(graph: CatalogGraph) {
	return Object.entries(graph.stogasEndpoints).sort(([a], [b]) => a.localeCompare(b));
}

function sortedDeployments(graph: CatalogGraph) {
	return Object.entries(graph.deployments).sort(([a], [b]) => {
		const rankDelta = deploymentRank(a) - deploymentRank(b);
		return rankDelta || a.localeCompare(b);
	});
}

function deploymentRank(id: string) {
	const rank = deploymentOrder.indexOf(id);
	return rank === -1 ? Number.MAX_SAFE_INTEGER : rank;
}

function groupedLayoutPositions(graph: CatalogGraph) {
	const positions = new Map<string, { x: number; y: number }>();
	const modelIds = unique(
		Object.values(graph.deployments).map((deployment) => String(deployment.modelId ?? '')).filter(Boolean)
	).sort((left, right) => modelLabel(graph, left).localeCompare(modelLabel(graph, right)));
	const deploymentIdsByModel = new Map<string, string[]>();
	for (const [deploymentId, deployment] of Object.entries(graph.deployments)) {
		const modelId = String(deployment.modelId ?? '');
		if (!modelId) continue;
		const deploymentIds = deploymentIdsByModel.get(modelId) ?? [];
		deploymentIds.push(deploymentId);
		deploymentIdsByModel.set(modelId, deploymentIds);
	}

	const deploymentStep = 90;
	const groupGap = 140;
	let cursor = 190;
	for (const modelId of modelIds) {
		const deploymentIds = (deploymentIdsByModel.get(modelId) ?? []).sort(
			(a, b) => deploymentRank(a) - deploymentRank(b) || deploymentLabel(graph, a).localeCompare(deploymentLabel(graph, b))
		);
		const span = Math.max(0, deploymentIds.length - 1) * deploymentStep;
		const center = cursor + span / 2;
		positions.set(nodeKey('model', modelId), lanePosition('model', center));
		deploymentIds.forEach((deploymentId, index) => {
			positions.set(nodeKey('deployment', deploymentId), lanePosition('deployment', cursor + index * deploymentStep));
		});
		cursor += span + groupGap;
	}

	const yFor = (key: string) => positions.get(key)?.y ?? null;
	const average = (values: Array<number | null>) => {
		const concrete = values.filter((value): value is number => typeof value === 'number');
		if (!concrete.length) return null;
		return concrete.reduce((sum, value) => sum + value, 0) / concrete.length;
	};
	const deploymentY = (deploymentId: string) => yFor(nodeKey('deployment', deploymentId));

	for (const authorId of unique(
		modelIds.map((modelId) => String(graph.models[modelId]?.authorId ?? '')).filter(Boolean)
	)) {
		const center = average(
			modelIds
				.filter((modelId) => String(graph.models[modelId]?.authorId ?? '') === authorId)
				.map((modelId) => yFor(nodeKey('model', modelId)))
		);
		if (center !== null) positions.set(nodeKey('author', authorId), lanePosition('author', center));
	}

	for (const providerId of Object.keys(graph.providers)) {
		const center = average(
			Object.entries(graph.deployments)
				.filter(([, deployment]) => String(deployment.providerId ?? '') === providerId)
				.map(([deploymentId]) => deploymentY(deploymentId))
		);
		if (center !== null) positions.set(nodeKey('provider', providerId), lanePosition('provider', center));
	}

	for (const [routeId] of Object.entries(graph.providerEndpoints)) {
		const center = average(deploymentIdsForProviderEndpoint(graph, routeId).map(deploymentY));
		if (center !== null)
			positions.set(nodeKey('providerEndpoint', routeId), lanePosition('providerEndpoint', center));
	}

	sortedStogasEndpoints(graph).forEach(([stogasEndpointId], index) => {
		positions.set(nodeKey('stogasEndpoint', stogasEndpointId), lanePosition('stogasEndpoint', 190 + index * 110));
	});

	return positions;
}

function lanePosition(type: NodeType, y: number) {
	return {
		x: laneX(type),
		y
	};
}

function fallbackNodePosition(type: NodeType) {
	return lanePosition(type, 190);
}

function laneX(type: NodeType) {
	const lane = graphChainNodeOrder.indexOf(type);
	return 80 + Math.max(0, lane) * 280;
}

function modelLabel(graph: CatalogGraph, modelId: string) {
	return String(graph.models[modelId]?.canonicalSlug ?? modelId);
}

function deploymentLabel(graph: CatalogGraph, deploymentId: string) {
	const deployment = graph.deployments[deploymentId];
	const aliases = deployment?.aliasSlugs;
	if (Array.isArray(aliases) && aliases.length) return String(aliases[0]);
	return deploymentId;
}

function nodeDetailsForModel(graph: CatalogGraph, modelId: string) {
	return {
		label: modelLabel(graph, modelId),
		subtitle: ''
	};
}

function nodeDetailsForDeployment(graph: CatalogGraph, deploymentId: string) {
	return {
		label: deploymentLabel(graph, deploymentId),
		subtitle: ''
	};
}

function makeNode(
	type: NodeType,
	id: string,
	position: { x: number; y: number },
	handles: GraphNodeData['handles'] = {},
	details: Partial<Pick<GraphNodeData, 'label' | 'subtitle'>> = {}
) {
	const data: GraphNodeData = {
		id,
		type,
		handles,
		label: details.label || id,
		subtitle: details.subtitle
	};
	return {
		id: nodeKey(type, id),
		type: 'catalog',
		data,
		position,
		class: `catalog-node catalog-node-${type}`,
		ariaRole: 'button' as const
	};
}

function edge(
	sourceType: NodeType,
	sourceId: string,
	targetType: NodeType,
	targetId: string,
	role: string,
	sourceHandle: string,
	targetHandle: string
) {
	return {
		id: `${nodeKey(sourceType, sourceId)}>${nodeKey(targetType, targetId)}`,
		source: nodeKey(sourceType, sourceId),
		target: nodeKey(targetType, targetId),
		sourceHandle,
		targetHandle,
		type: 'smoothstep',
		class: `catalog-edge catalog-edge-${role}`,
		markerEnd: {
			type: MarkerType.ArrowClosed,
			width: 14,
			height: 14
		}
	};
}

export function decorateFlow(
	flow: CatalogFlow,
	currentKey: string,
	currentEdgeId = '',
	selectedKeys: string[] = [],
	graphChains: GraphChain[] = []
): CatalogFlow {
	const selected = new Set(selectedKeys);
	if (!selected.size && currentKey) selected.add(currentKey);
	const visibleEdges = visibleEdgeIdsForSelection(flow, selected, graphChains);
	const activeEdges = activeEdgeIdsForSelection(flow, selected, visibleEdges);
	const related = edgeEndpointKeys(flow, visibleEdges, selected);
	const hasSelection = selected.size > 0;
	return {
		nodes: flow.nodes.map((node) => ({
			...node,
			class:
				`${node.class ?? ''} ${related.has(node.id) ? 'catalog-node-related' : ''} ${selected.has(node.id) ? 'catalog-node-active' : ''} ${node.id === currentKey ? 'catalog-node-current' : ''}`.trim()
		})),
		edges: flow.edges.map((edge) => ({
			...edge,
			hidden:
				hasSelection && !visibleEdges.has(String(edge.id)) && String(edge.id) !== currentEdgeId,
			class:
				`${edge.class ?? ''} ${activeEdges.has(String(edge.id)) ? 'catalog-edge-active' : ''} ${String(edge.id) === currentEdgeId ? 'catalog-edge-current' : ''}`.trim()
		}))
	};
}

export function concreteGraphChains(catalog: Catalog): GraphChain[] {
	const graph = catalog.graph;
	const chains: GraphChain[] = [];
	for (const [deploymentId, deployment] of Object.entries(graph.deployments)) {
		const modelId = String(deployment.modelId ?? '');
		const model = graph.models[modelId];
		const authorId = String(model?.authorId ?? '');
		const providerId = String(deployment.providerId ?? '');
		for (const routeId of parentProviderEndpointNodesForDeployment(graph, deploymentId)) {
			const route = graph.providerEndpoints[routeId];
			for (const stogasEndpointId of stogasEndpointIdsForProviderEndpoint(route)) {
				chains.push({
					edgeIds: [
						graphEdgeId('author', authorId, 'model', modelId),
						graphEdgeId('model', modelId, 'deployment', deploymentId),
						graphEdgeId('provider', providerId, 'providerEndpoint', routeId),
						graphEdgeId('providerEndpoint', routeId, 'deployment', deploymentId)
					].filter(Boolean),
					nodeKeys: [
						nodeKey('author', authorId),
						nodeKey('model', modelId),
						nodeKey('deployment', deploymentId),
						nodeKey('providerEndpoint', routeId),
						nodeKey('provider', providerId),
						nodeKey('stogasEndpoint', stogasEndpointId)
					].filter((key) => !key.endsWith(':'))
				});
			}
		}
	}
	return chains;
}

export function extendGraphSelection(
	flow: CatalogFlow,
	graphChains: GraphChain[],
	selectedKeys: string[],
	nextKey: string
) {
	if (!selectedKeys.length) return [nextKey];
	if (selectedKeys.includes(nextKey)) return selectedKeys;
	const nextKeys = [...selectedKeys, nextKey];
	const graphNodeKeys = new Set(flow.nodes.map((node) => node.id));
	if (!graphNodeKeys.has(nextKey)) return null;
	const chain = graphChains.find(
		(chain) => graphNodeKeys.has(nextKey) && nextKeys.every((key) => chain.nodeKeys.includes(key))
	);
	if (!chain) return null;
	const nextIndex = chain.nodeKeys.indexOf(nextKey);
	const nearestSelected = selectedKeys
		.map((key) => ({ index: chain.nodeKeys.indexOf(key), key }))
		.filter((item) => item.index !== -1)
		.sort((a, b) => Math.abs(a.index - nextIndex) - Math.abs(b.index - nextIndex))[0];
	if (!nearestSelected) return [...selectedKeys, nextKey];
	const [from, to] =
		nearestSelected.index < nextIndex
			? [nearestSelected.index, nextIndex]
			: [nextIndex, nearestSelected.index];
	return unique([...selectedKeys, ...chain.nodeKeys.slice(from, to + 1)]);
}

export function completeUnambiguousGraphSelection(
	graphChains: GraphChain[],
	selectedKeys: string[]
) {
	if (!selectedKeys.length) return selectedKeys;
	const matchingChains = graphChains.filter((chain) =>
		selectedKeys.every((key) => chain.nodeKeys.includes(key))
	);
	if (!matchingChains.length) return selectedKeys;
	const requiredByType = new Map<NodeType, string>();
	for (const nodeKey of selectedKeys) {
		const parsed = parseNodeKey(nodeKey);
		if (parsed) requiredByType.set(parsed.type, nodeKey);
	}
	for (const type of graphChainNodeOrder) {
		if (requiredByType.has(type)) continue;
		const candidates = unique(
			matchingChains
				.map((chain) => chain.nodeKeys.find((key) => parseNodeKey(key)?.type === type) ?? '')
				.filter(Boolean)
		);
		if (candidates.length === 1) requiredByType.set(type, candidates[0]);
	}
	return graphChainNodeOrder.map((type) => requiredByType.get(type) ?? '').filter(Boolean);
}

export function filterFlow(
	flow: CatalogFlow,
	visibleTypes: Record<string, boolean>,
	query = '',
	selectedKeys: string[] = [],
	graphChains: GraphChain[] = []
): CatalogFlow {
	const needle = query.trim().toLowerCase();
	const compatibleNodeKeys = compatibleNodeKeysForSelection(selectedKeys, graphChains);
	const nodes = flow.nodes.filter((node) => {
		const type = node.data.type;
		if (compatibleNodeKeys && !compatibleNodeKeys.has(node.id)) return false;
		if (visibleTypes[type] === false) return false;
		if (!needle) return true;
		return (
			node.data.id.toLowerCase().includes(needle) ||
			node.data.label.toLowerCase().includes(needle) ||
			type.toLowerCase().includes(needle)
		);
	});
	const visibleNodeIds = new Set(nodes.map((node) => node.id));
	const edges = flow.edges.filter(
		(edge) =>
			!edge.hidden &&
			visibleNodeIds.has(String(edge.source)) &&
			visibleNodeIds.has(String(edge.target))
	);
	return compactFlowLayout(nodes, edges);
}

function visibleEdgeIdsForSelection(
	flow: CatalogFlow,
	selectedNodes: Set<string>,
	graphChains: GraphChain[]
) {
	if (!selectedNodes.size) return new Set(flow.edges.map((edge) => String(edge.id)));
	const ids = new Set<string>();
	for (const chain of graphChains) {
		if (![...selectedNodes].every((key) => chain.nodeKeys.includes(key))) continue;
		for (const edgeId of chain.edgeIds) ids.add(edgeId);
	}
	return ids;
}

function activeEdgeIdsForSelection(
	flow: CatalogFlow,
	selectedNodes: Set<string>,
	visibleEdgeIds: Set<string>
) {
	const ids = new Set<string>();
	for (const edge of flow.edges) {
		const edgeId = String(edge.id);
		if (!visibleEdgeIds.has(edgeId)) continue;
		if (selectedNodes.has(String(edge.source)) && selectedNodes.has(String(edge.target))) {
			ids.add(edgeId);
		}
	}
	return ids;
}

function edgeEndpointKeys(flow: CatalogFlow, edgeIds: Set<string>, activeNodes: Set<string>) {
	const keys = new Set<string>();
	for (const edge of flow.edges) {
		if (!edgeIds.has(String(edge.id))) continue;
		const source = String(edge.source);
		const target = String(edge.target);
		if (!activeNodes.has(source)) keys.add(source);
		if (!activeNodes.has(target)) keys.add(target);
	}
	return keys;
}

function compatibleNodeKeysForSelection(selectedKeys: string[], graphChains: GraphChain[]) {
	if (!selectedKeys.length) return null;
	const keys = new Set<string>();
	for (const chain of graphChains) {
		if (!selectedKeys.every((key) => chain.nodeKeys.includes(key))) continue;
		for (const nodeKey of chain.nodeKeys) keys.add(nodeKey);
	}
	for (const selectedKey of selectedKeys) keys.add(selectedKey);
	return keys;
}

function compactFlowLayout(nodes: Node<GraphNodeData>[], edges: Edge[]): CatalogFlow {
	return { nodes, edges };
}

function unique<T>(items: T[]) {
	return [...new Set(items)];
}

function graphEdgeId(
	sourceType: NodeType,
	sourceId: string,
	targetType: NodeType,
	targetId: string
) {
	if (!sourceId || !targetId) return '';
	return `${nodeKey(sourceType, sourceId)}>${nodeKey(targetType, targetId)}`;
}

export function parentProviderEndpointNodesForDeployment(
	graph: CatalogGraph,
	deploymentId: string
) {
	const deployment = graph.deployments[deploymentId];
	const ids = deployment?.parentProviderEndpointNodes;
	return Array.isArray(ids) ? ids.map(String).sort() : [];
}

export function deploymentIdsForModel(graph: CatalogGraph, modelId: string) {
	return Object.entries(graph.deployments)
		.filter(([, deployment]) => deployment.modelId === modelId)
		.map(([id]) => id)
		.sort((a, b) => deploymentRank(a) - deploymentRank(b) || a.localeCompare(b));
}

export function firstProviderEndpointForDeployment(graph: CatalogGraph, deploymentId: string) {
	return parentProviderEndpointNodesForDeployment(graph, deploymentId)[0] ?? '';
}

export function firstDeploymentForProviderEndpoint(graph: CatalogGraph, routeId: string) {
	return deploymentIdsForProviderEndpoint(graph, routeId)[0] ?? '';
}

export function deploymentIdsForProviderEndpoint(graph: CatalogGraph, routeId: string) {
	return Object.entries(graph.deployments)
		.filter(([, deployment]) => {
			const endpointIds = deployment.parentProviderEndpointNodes;
			return Array.isArray(endpointIds) && endpointIds.includes(routeId);
		})
		.map(([id]) => id)
		.sort((a, b) => deploymentRank(a) - deploymentRank(b) || a.localeCompare(b));
}

export function lineageForSelection(
	catalog: Catalog,
	selectedKey: string,
	context: { routeId?: string; deploymentId?: string }
): LineageNode[] {
	const parsed = parseNodeKey(selectedKey);
	if (!parsed) return [];
	const concrete = contextLineage(catalog, parsed, context);
	if (concrete) return concrete;

	if (parsed.type === 'deployment') {
		if (!context.routeId) {
			return lineageForDeploymentModel(catalog, parsed.id);
		}
		return lineageForDeployment(catalog, parsed.id, context.routeId);
	}
	if (parsed.type === 'providerEndpoint') {
		const route = catalog.graph.providerEndpoints[parsed.id];
		if (!route) return [];
		if (context.deploymentId) return lineageForDeployment(catalog, context.deploymentId, parsed.id);
		const providerId = String(route.providerId);
		return [
			stogasEndpointForProviderEndpoint(catalog.graph, route),
			source('provider', providerId, catalog.graph.providers[providerId]),
			source('providerEndpoint', parsed.id, route)
		];
	}
	if (parsed.type === 'model') {
		const model = catalog.graph.models[parsed.id];
		if (!model) return [];
		const authorId = String(model.authorId);
		if (context.deploymentId && context.routeId) {
			return lineageForDeployment(catalog, context.deploymentId, context.routeId);
		}
		if (context.deploymentId) {
			return lineageForDeploymentModel(catalog, context.deploymentId);
		}
		return [
			source('author', authorId, catalog.graph.authors[authorId]),
			source('model', parsed.id, model)
		];
	}
	if (parsed.type === 'provider') {
		return [source('provider', parsed.id, catalog.graph.providers[parsed.id])];
	}
	if (parsed.type === 'author') {
		return [source('author', parsed.id, catalog.graph.authors[parsed.id])];
	}
	const value = valueForNode(catalog.graph, parsed.type, parsed.id);
	return value ? [source(parsed.type, parsed.id, value)] : [];
}

function contextLineage(
	catalog: Catalog,
	selected: { type: NodeType; id: string },
	context: { routeId?: string; deploymentId?: string }
) {
	if (context.deploymentId && context.routeId) {
		const lineage = lineageForDeployment(catalog, context.deploymentId, context.routeId);
		if (lineageContains(lineage, selected)) return lineage;
	}
	if (context.deploymentId) {
		const lineage = lineageForDeploymentModel(catalog, context.deploymentId);
		if (lineageContains(lineage, selected)) return lineage;
	}
	if (context.routeId) {
		const lineage = lineageForProviderEndpoint(catalog, context.routeId);
		if (lineageContains(lineage, selected)) return lineage;
	}
	return null;
}

function lineageForProviderEndpoint(catalog: Catalog, routeId: string) {
	const route = catalog.graph.providerEndpoints[routeId];
	if (!route) return [];
	const providerId = String(route.providerId);
	return [
		stogasEndpointForProviderEndpoint(catalog.graph, route),
		source('provider', providerId, catalog.graph.providers[providerId]),
		source('providerEndpoint', routeId, route)
	];
}

function lineageContains(lineage: LineageNode[], selected: { type: NodeType; id: string }) {
	return lineage.some((node) => node.type === selected.type && node.id === selected.id);
}

function lineageForDeployment(catalog: Catalog, deploymentId: string, preferredRouteId = '') {
	const graph = catalog.graph;
	const deployment = graph.deployments[deploymentId];
	if (!deployment) return [firstStogasEndpointNode(graph)];
	const model = graph.models[String(deployment.modelId)];
	const author = graph.authors[String(model.authorId)];
	const provider = graph.providers[String(deployment.providerId)];
	const routeId = preferredRouteId || firstProviderEndpointForDeployment(graph, deploymentId);
	const route = graph.providerEndpoints[routeId];

	return [
		...(route ? [stogasEndpointForProviderEndpoint(graph, route)] : []),
		source('author', String(model.authorId), author),
		source('model', String(deployment.modelId), model),
		source('provider', String(deployment.providerId), provider),
		...(route ? [source('providerEndpoint', routeId, route)] : []),
		source('deployment', deploymentId, deployment)
	];
}

function lineageForDeploymentModel(catalog: Catalog, deploymentId: string) {
	const graph = catalog.graph;
	const deployment = graph.deployments[deploymentId];
	if (!deployment) return [firstStogasEndpointNode(graph)];
	const model = graph.models[String(deployment.modelId)];
	const author = graph.authors[String(model.authorId)];

	return [
		source('author', String(model.authorId), author),
		source('model', String(deployment.modelId), model),
		source('deployment', deploymentId, deployment)
	];
}

function firstStogasEndpointNode(graph: CatalogGraph) {
	const [id, value] = Object.entries(graph.stogasEndpoints)[0] ?? [];
	return source('stogasEndpoint', id ?? 'stogasEndpoint', value ?? {});
}

function stogasEndpointForProviderEndpoint(graph: CatalogGraph, route?: Record<string, unknown>) {
	const stogasEndpointId = stogasEndpointIdsForProviderEndpoint(route)[0] ?? '';
	if (stogasEndpointId && graph.stogasEndpoints[stogasEndpointId])
		return source('stogasEndpoint', stogasEndpointId, graph.stogasEndpoints[stogasEndpointId]);
	return firstStogasEndpointNode(graph);
}

function stogasEndpointIdsForProviderEndpoint(route?: Record<string, unknown>) {
	if (!route) return [];
	if (Array.isArray(route.stogasEndpoints)) return route.stogasEndpoints.map(String).filter(Boolean);
	return [];
}

function source(type: NodeType, id: string, value: Record<string, unknown>): LineageNode {
	return { type, id, value };
}

function valueForNode(graph: CatalogGraph, type: NodeType, id: string): Record<string, unknown> {
	if (type === 'location') return graph.locations.nodes[id];
	const collection = `${type}s` as keyof CatalogGraph;
	return (graph[collection] as Record<string, Record<string, unknown>>)[id];
}
