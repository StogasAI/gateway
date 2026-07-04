<script lang="ts">
	import {
		Background,
		BackgroundVariant,
		Controls,
		MiniMap,
		SvelteFlow,
		type Edge,
		type Node,
		type NodeTypes
	} from '@xyflow/svelte';
	import '@xyflow/svelte/dist/style.css';
	import catalogJson from '../../../transports/stogas/catalog/generated/catalog.json';
	import CatalogNode from './CatalogNode.svelte';
	import {
		buildFlow,
		completeUnambiguousGraphSelection,
		concreteGraphChains,
		decorateFlow,
		extendGraphSelection,
		filterFlow,
		lineageForSelection,
		nodeKey,
		parseNodeKey
	} from './catalog';
	import type { Catalog, LineageNode, NodeType, SourcePayload } from './types';

	const catalog = catalogJson as Catalog;
	const nodeTypes: NodeTypes = { catalog: CatalogNode };
	const nodeTypeOptions: NodeType[] = [
		'stogasEndpoint',
		'author',
		'model',
		'deployment',
		'providerEndpoint',
		'provider'
	];
	type UiTheme = 'dark' | 'light';

	let selectedKey = $state('');
	let selectedEdgeId = $state('');
	let selectedGraphKeys = $state<string[]>([]);
	let uiTheme = $state<UiTheme>('dark');
	let themeLoaded = $state(false);
	let contextRouteId = $state('');
	let contextDeploymentId = $state('');
	let nodeFilter = $state('');
	let compatibleOnly = $state(false);
	let visibleNodeTypes = $state<Record<NodeType, boolean>>({
		stogasEndpoint: true,
		author: true,
		model: true,
		provider: true,
		providerEndpoint: true,
		deployment: true,
		location: true
	});
	let inspectorWidth = $state(500);
	let sources = $state<SourcePayload | null>(null);
	let activePath = $state('');
	let draft = $derived(sourceContent(activePath));
	let sourceStatus = $state('');
	let buildStatus = $state('');

	const selected = $derived(parseNodeKey(selectedKey));
	const flow = $derived(buildFlow(catalog.graph));
	const graphChains = $derived(concreteGraphChains(catalog));
	const lineage = $derived(
		lineageForSelection(catalog, selectedKey, {
			routeId: contextRouteId,
			deploymentId: contextDeploymentId
		})
	);
	const visibleLineage = $derived(dedupedVisibleLineage(lineage));
	const decoratedFlow = $derived(
		decorateFlow(flow, selectedKey, selectedEdgeId, selectedGraphKeys, graphChains)
	);
	const filteredFlow = $derived(
		filterFlow(
			decoratedFlow,
			visibleNodeTypes,
			nodeFilter,
			compatibleOnly ? selectedGraphKeys : [],
			graphChains
		)
	);
	const sourcePaths = $derived(sources?.nodeSources[selectedKey] ?? []);
	const flowEvents = {
		onedgeclick: selectEdge,
		onnodeclick: selectNode,
		onpaneclick: clearSelection
	};

	$effect(() => {
		if (themeLoaded) return;
		const stored = globalThis.localStorage?.getItem('catalog-editor-theme');
		if (stored === 'dark' || stored === 'light') uiTheme = stored;
		themeLoaded = true;
	});

	$effect(() => {
		if (!themeLoaded) return;
		globalThis.localStorage?.setItem('catalog-editor-theme', uiTheme);
	});

	$effect(() => {
		fetch('/api/catalog/sources')
			.then((response) => response.json())
			.then((payload: SourcePayload) => {
				sources = payload;
			})
			.catch((error) => {
				sourceStatus = error instanceof Error ? error.message : String(error);
			});
	});

	$effect(() => {
		if (!sourcePaths.includes(activePath)) activePath = sourcePaths[0] ?? '';
	});

	function selectNode(event: { node: Node }) {
		selectGraphNode(event.node.id);
	}

	function selectChainNode(type: NodeType, id: string) {
		const key = nodeKey(type, id);
		if (selectedGraphKeys.includes(key)) {
			setCurrentKey(key);
			return;
		}
		setGraphSelection([key]);
		setCurrentKey(key);
	}

	function setCurrentKey(key: string) {
		selectedKey = key;
		selectedEdgeId = '';
		sourceStatus = '';
		buildStatus = '';
	}

	function replaceSelection(key: string) {
		setGraphSelection([key]);
		setCurrentKey(key);
	}

	function clearSelection() {
		selectedGraphKeys = [];
		contextDeploymentId = '';
		contextRouteId = '';
		setCurrentKey('');
	}

	function selectGraphNode(key: string) {
		const next = parseNodeKey(key);
		if (!next) {
			clearSelection();
			return;
		}
		if (selectedGraphKeys.includes(key)) {
			setCurrentKey(key);
			return;
		}
		const nextSelection = extendGraphSelection(flow, graphChains, selectedGraphKeys, key);
		if (nextSelection) {
			setGraphSelection(nextSelection);
			setCurrentKey(key);
			return;
		}
		replaceSelection(key);
	}

	function setGraphSelection(keys: string[]) {
		selectedGraphKeys = completeUnambiguousGraphSelection(graphChains, keys);
		syncGraphContext(selectedGraphKeys);
	}

	function selectEdge(event: CustomEvent<{ edge: Edge }> | { edge: Edge }) {
		const edge = 'detail' in event ? event.detail.edge : event.edge;
		selectedEdgeId = String(edge.id);
	}

	function toggleNodeType(type: NodeType) {
		visibleNodeTypes = { ...visibleNodeTypes, [type]: !visibleNodeTypes[type] };
	}

	function toggleCompatibleOnly() {
		compatibleOnly = !compatibleOnly;
	}

	function setTheme(theme: UiTheme) {
		uiTheme = theme;
	}

	function syncGraphContext(keys: string[]) {
		const parsed = keys.map(parseNodeKey).filter(Boolean);
		contextDeploymentId = parsed.find((node) => node.type === 'deployment')?.id ?? '';
		contextRouteId = parsed.find((node) => node.type === 'providerEndpoint')?.id ?? '';
	}

	function sourceContent(path: string) {
		return sources?.files.find((file) => file.path === path)?.content ?? '';
	}

	async function buildCatalog() {
		buildStatus = 'Building...';
		const response = await fetch('/api/catalog/build', { method: 'POST' });
		const payload = (await response.json()) as { ok: boolean; output: string };
		buildStatus = payload.ok ? 'Build passed' : payload.output;
	}

	async function saveSource() {
		if (!activePath) return;
		sourceStatus = 'Saving...';
		const response = await fetch('/api/catalog/source', {
			method: 'PUT',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ path: activePath, content: draft })
		});
		if (!response.ok) {
			sourceStatus = await response.text();
			return;
		}
		if (sources) {
			sources = {
				...sources,
				files: sources.files.map((file) =>
					file.path === activePath ? { ...file, content: draft } : file
				)
			};
		}
		sourceStatus = 'Saved';
	}

	function attributeLabel(value: string) {
		return value
			.replace(/([a-z0-9])([A-Z])/g, '$1 $2')
			.replaceAll('_', ' ')
			.toLowerCase();
	}

	function nodeTypeLabel(type: NodeType) {
		return attributeLabel(type);
	}

	function dedupedVisibleLineage(nodes: LineageNode[]) {
		const seen = new Set<string>();
		const visible: LineageNode[] = [];
		for (const node of nodes) {
			const key = nodeKey(node.type, node.id);
			if (seen.has(key)) continue;
			seen.add(key);
			visible.push(node);
		}
		return visible;
	}

	function startResize(event: PointerEvent) {
		const startX = event.clientX;
		const startWidth = inspectorWidth;
		const move = (moveEvent: PointerEvent) => {
			inspectorWidth = Math.max(360, Math.min(840, startWidth - (moveEvent.clientX - startX)));
		};
		const stop = () => {
			window.removeEventListener('pointermove', move);
			window.removeEventListener('pointerup', stop);
		};
		window.addEventListener('pointermove', move);
		window.addEventListener('pointerup', stop);
	}
</script>

<main
	class="shell"
	data-theme={uiTheme}
	style:grid-template-columns={`minmax(0, 1fr) 6px ${inspectorWidth}px`}
>
	<section class="graph-pane" aria-label="Catalog graph">
		<div class="bar">
			<div>
				<h1>Catalog Graph</h1>
				<p>
					{Object.keys(catalog.graph.deployments).length} deployments, {Object.keys(
						catalog.graph.providerEndpoints
					).length} provider endpoints
				</p>
			</div>
			<div class="legend" aria-label="Node type legend">
				<span data-type="stogasEndpoint">stogas endpoint</span>
				<span data-type="author">author</span>
				<span data-type="model">model</span>
				<span data-type="provider">provider</span>
				<span data-type="providerEndpoint">provider endpoint</span>
				<span data-type="deployment">deployment</span>
			</div>
			<div class="toolbar-actions">
				{#if buildStatus}<p class="bar-status">{buildStatus}</p>{/if}
				<div class="segmented theme-switch" aria-label="Theme">
					<button
						type="button"
						class:active={uiTheme === 'dark'}
						aria-pressed={uiTheme === 'dark'}
						onclick={() => setTheme('dark')}>Dark</button
					>
					<button
						type="button"
						class:active={uiTheme === 'light'}
						aria-pressed={uiTheme === 'light'}
						onclick={() => setTheme('light')}>Light</button
					>
				</div>
				<button type="button" onclick={buildCatalog}>Build</button>
			</div>
		</div>
		<div class="graph-filters" aria-label="Graph filters">
			<input bind:value={nodeFilter} placeholder="Filter nodes" aria-label="Filter nodes" />
			<div class="filter-chips" aria-label="Node type filters">
				<label data-type="compatible">
					<input type="checkbox" checked={compatibleOnly} onchange={toggleCompatibleOnly} />
					<span>Compatible</span>
				</label>
				{#each nodeTypeOptions as type (type)}
					<label data-type={type}>
						<input
							type="checkbox"
							checked={visibleNodeTypes[type]}
							onchange={() => toggleNodeType(type)}
						/>
						<span>{attributeLabel(type)}</span>
					</label>
				{/each}
			</div>
		</div>
		<div class="flow">
			<div class="graph-guide" aria-hidden="true">
				<span>author</span>
				<span>model</span>
				<span>deployment</span>
				<span>provider endpoint</span>
				<span>provider</span>
				<span>stogas endpoint</span>
			</div>
			<SvelteFlow
				nodes={filteredFlow.nodes}
				edges={filteredFlow.edges}
				{nodeTypes}
				fitView
				fitViewOptions={{ padding: 0.13 }}
				minZoom={0.2}
				maxZoom={1.8}
				nodesDraggable={false}
				nodesConnectable={false}
				elementsSelectable={false}
				colorMode={uiTheme}
				{...flowEvents}
			>
				<Controls />
				<MiniMap pannable zoomable nodeStrokeWidth={3} />
				<Background variant={BackgroundVariant.Lines} />
			</SvelteFlow>
		</div>
	</section>

	<button
		class="splitter"
		type="button"
		aria-label="Resize details panel"
		onpointerdown={startResize}
	></button>

	<aside class="inspector" aria-label="Selected node details">
		<header class="inspector-head">
			<div>
				<span>{selected ? nodeTypeLabel(selected.type) : 'node'}</span>
				<h2>{selected?.id ?? 'Select a node'}</h2>
			</div>
		</header>

		<section class="chain-card" aria-label="Inheritance chain">
			<div class="section-head">
				<div>
					<span>Context</span>
					<strong>{visibleLineage.length ? `${visibleLineage.length} nodes` : 'No selection'}</strong>
				</div>
			</div>
			<div class="chain-row">
				{#each visibleLineage as node (nodeKey(node.type, node.id))}
					<button
						type="button"
						class="chain-node"
						data-type={node.type}
						aria-current={nodeKey(node.type, node.id) === selectedKey ? 'true' : undefined}
						onclick={() => selectChainNode(node.type, node.id)}
					>
						<span>{nodeTypeLabel(node.type)}</span>
						<strong>{node.id}</strong>
					</button>
				{/each}
			</div>
		</section>

		<section class="source-card" aria-label="Raw source file">
			<div class="source-head">
				<div>
					<span>Raw file</span>
					<strong>{activePath ? 'Source' : 'No source file'}</strong>
				</div>
				<div class="source-actions">
					<button type="button" onclick={saveSource} disabled={!activePath}>Save</button>
				</div>
			</div>
			{#if sourcePaths.length > 1}
				<select bind:value={activePath} aria-label="Raw source file">
					{#each sourcePaths as path (path)}
						<option value={path}>{path}</option>
					{/each}
				</select>
			{/if}
			{#if activePath}
				<textarea bind:value={draft} spellcheck="false" aria-label="Raw catalog source"></textarea>
			{:else}
				<p class="empty">Select a graph node with a source file.</p>
			{/if}
			{#if sourceStatus}<p class="status">{sourceStatus}</p>{/if}
		</section>

	</aside>
</main>
