import type { Edge, Node } from '@xyflow/svelte';

export type NodeType =
	| 'stogasEndpoint'
	| 'author'
	| 'model'
	| 'provider'
	| 'providerEndpoint'
	| 'deployment'
	| 'location';

export type CatalogGraph = {
	stogas: Record<string, unknown>;
	stogasEndpoints: Record<string, Record<string, unknown>>;
	locations: { nodes: Record<string, Record<string, unknown>> };
	authors: Record<string, Record<string, unknown>>;
	models: Record<string, Record<string, unknown>>;
	providers: Record<string, Record<string, unknown>>;
	providerEndpoints: Record<string, Record<string, unknown>>;
	deployments: Record<string, Record<string, unknown>>;
};

export type Catalog = {
	graph: CatalogGraph;
	indexes: Record<string, unknown>;
};

export type GraphNodeData = {
	label: string;
	type: NodeType;
	id: string;
	subtitle?: string;
	count?: number;
	handles?: {
		leftIn?: boolean;
		leftOut?: boolean;
		rightIn?: boolean;
		rightOut?: boolean;
	};
};

export type LineageNode = {
	type: NodeType;
	id: string;
	value: Record<string, unknown>;
};

export type CatalogFlow = {
	nodes: Node<GraphNodeData>[];
	edges: Edge[];
};

export type GraphChain = {
	edgeIds: string[];
	nodeKeys: string[];
};

export type SourceFile = {
	path: string;
	content: string;
};

export type SourcePayload = {
	files: SourceFile[];
	nodeSources: Record<string, string[]>;
};
