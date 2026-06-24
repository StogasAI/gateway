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
	import { SvelteMap } from 'svelte/reactivity';
	import catalogJson from '../../../transports/stogas/catalog/generated/catalog.json';
	import CatalogNode from './CatalogNode.svelte';
	import {
		buildFlow,
		completeUnambiguousGraphSelection,
		concreteAttributes,
		concreteGraphChains,
		decorateFlow,
		definedAttributes,
		displayValue,
		extendGraphSelection,
		filterFlow,
		lineageForSelection,
		nodeKey,
		parseNodeKey,
		selectedOwnerKey
	} from './catalog';
	import type { AttributeTrace, Catalog, LineageNode, NodeType, SourcePayload } from './types';

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
	type TraceRow = AttributeTrace & { displayPath: string };
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
	let traceFilter = $state('');
	let attributeScope = $state<'selected' | 'inherited'>('selected');
	let ownerFilter = $state('all');
	let overrideOnly = $state(false);
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
	const selectedOwner = $derived(selectedOwnerKey(selectedKey, lineage));
	const ownerOptions = $derived(lineage.map((node) => nodeKey(node.type, node.id)));
	const sourcePaths = $derived(sources?.nodeSources[selectedKey] ?? []);
	const traces = $derived(
		(attributeScope === 'selected'
			? definedAttributes(lineage, selectedOwner)
			: concreteAttributes(lineage).filter(
					(trace) => ownerFilter === 'all' || trace.owner === ownerFilter
				)
		)
			.filter(
				(trace) => attributeScope !== 'inherited' || !overrideOnly || trace.status === 'overrides'
			)
			.filter((trace) => matchesTrace(trace, traceFilter))
	);
	const schemaPolicyKeys = $derived(collectSchemaPolicyKeys(lineage));
	const traceGroups = $derived(groupTraces(traces, schemaPolicyKeys));
	const hasTraceGroups = $derived(traceGroups.some((section) => traceSectionCount(section) > 0));
	const directAttributes = $derived(
		traceGroups.find((section) => section.key === 'attributes')?.attributes ?? []
	);
	const sectionedTraceGroups = $derived(
		traceGroups.filter((section) => section.key !== 'attributes')
	);
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
		if (ownerFilter !== 'all' && !ownerOptions.includes(ownerFilter)) ownerFilter = 'all';
	});

	$effect(() => {
		if (attributeScope === 'selected') {
			ownerFilter = 'all';
			overrideOnly = false;
		}
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
		attributeScope = 'selected';
		ownerFilter = 'all';
		overrideOnly = false;
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

	function matchesTrace(trace: { path: string; owner: string; value: unknown }, filter: string) {
		if (!filter.trim()) return true;
		const needle = filter.toLowerCase();
		return (
			trace.path.toLowerCase().includes(needle) ||
			trace.owner.toLowerCase().includes(needle) ||
			displayValue(trace.value).toLowerCase().includes(needle)
		);
	}

	function traceTitle(trace: {
		status?: string;
		owner: string;
		previousOwner?: string;
		previousValue?: unknown;
		value?: unknown;
	}) {
		if (!trace.previousOwner) return `Owner ${trace.owner}`;
		return `${attributeChange(trace as AttributeTrace)} ${trace.previousOwner}: ${displayValue(
			trace.previousValue
		)}`;
	}

	function policyDetails(trace: AttributeTrace) {
		return trace.policyEntries ?? [];
	}

	function displayRuleName(name: string) {
		return name.replaceAll('.', ' ').replaceAll('_', ' ');
	}

	function displayRuleValue(value: unknown) {
		const text = displayValue(value);
		return text.length > 80 ? `${text.slice(0, 77)}...` : text;
	}

	function valuePreview(value: unknown, max = 140) {
		if (value === '(policy)') return 'policy only';
		const text = displayValue(value);
		return text.length > max ? `${text.slice(0, Math.max(0, max - 3))}...` : text;
	}

	function isExpandableValue(value: unknown) {
		return displayValue(value).length > 180 || (value && typeof value === 'object');
	}

	function ownerId(owner: string) {
		return owner.split(':').slice(1).join(':');
	}

	function collectSchemaPolicyKeys(nodes: LineageNode[]) {
		const keys = new Set<string>();
		for (const node of nodes) {
			const schema = objectRecord(node.value.schema);
			for (const section of ['headers', 'parameters']) {
				const policies = objectRecord(schema?.[section]);
				if (!policies) continue;
				for (const name of Object.keys(policies)) keys.add(`schema.${section}.${name}`);
			}
		}
		return [...keys].sort((a, b) => b.length - a.length);
	}

	function objectRecord(value: unknown) {
		if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
		return value as Record<string, unknown>;
	}

	function groupTraces(items: AttributeTrace[], policyKeys: string[]) {
		const sections = new SvelteMap<
			string,
			{
				attributes: SvelteMap<string, TraceRow[]>;
				label: string;
				subsections: SvelteMap<
					string,
					{
						attributes: SvelteMap<string, TraceRow[]>;
						label: string;
					}
				>;
			}
		>();
		for (const trace of items) {
			const placement = tracePlacement(trace.path, policyKeys);
			const { attributeKey, displayPath, sectionKey, subsectionKey } = placement;
			let section = sections.get(sectionKey);
			if (!section) {
				section = {
					attributes: new SvelteMap(),
					label: groupLabel(sectionKey),
					subsections: new SvelteMap()
				};
				sections.set(sectionKey, section);
			}
			const container = subsectionKey
				? (section.subsections.get(subsectionKey) ?? {
						attributes: new SvelteMap<string, TraceRow[]>(),
						label: groupLabel(subsectionKey)
					})
				: section;
			if (subsectionKey && !section.subsections.has(subsectionKey)) {
				section.subsections.set(subsectionKey, container);
			}
			const rows = container.attributes.get(attributeKey) ?? [];
			rows.push({ ...trace, displayPath });
			container.attributes.set(attributeKey, rows);
		}
		return [...sections.entries()].map(([key, section]) => ({
			attributes: [...section.attributes.entries()].map(([attribute, rows]) =>
				attributeGroup(key, attribute, rows)
			),
			key,
			label: section.label,
			subsections: [...section.subsections.entries()].map(([subsectionKey, subsection]) => ({
				attributes: [...subsection.attributes.entries()].map(([attribute, rows]) =>
					attributeGroup(`${key}:${subsectionKey}`, attribute, rows)
				),
				key: subsectionKey,
				label: subsection.label
			}))
		}));
	}

	function attributeGroup(sectionKey: string, attribute: string, rows: TraceRow[]) {
		const compactRows = compactPolicyRows(rows);
		return {
			changeTags: attributeChangeTags(compactRows),
			key: `${sectionKey}:${attribute}`,
			label: attributeLabel(attribute),
			owners: unique(compactRows.map((row) => row.owner)),
			preview: attributePreview(compactRows),
			rows: compactRows
		};
	}

	function traceSectionCount(section: {
		attributes: unknown[];
		subsections?: { attributes: unknown[] }[];
	}) {
		return (
			section.attributes.length +
			(section.subsections ?? []).reduce(
				(count, subsection) => count + subsection.attributes.length,
				0
			)
		);
	}

	function attributePreview(rows: TraceRow[]) {
		if (!rows.length) return '';
		if (rows.length === 1) return valuePreview(rows[0].value, 92);
		const compact = rows
			.slice(0, 3)
			.map((row) =>
				row.displayPath
					? `${attributeLabel(row.displayPath)}: ${valuePreview(row.value, 34)}`
					: valuePreview(row.value, 42)
			)
			.join(', ');
		return rows.length > 3 ? `${compact}, ${rows.length - 3} more` : compact;
	}

	function attributeFullValue(attribute: { label: string; rows: TraceRow[] }) {
		const rows = attribute.rows.filter((row) => row.value !== '(policy)');
		if (!rows.length) return null;
		const value =
			rows.length === 1
				? rows[0].value
				: Object.fromEntries(rows.map((row) => [row.displayPath || attribute.label, row.value]));
		return isExpandableValue(value) ? { value } : null;
	}

	function rowHasDetails(row: TraceRow) {
		return Boolean(row.previousOwner || policyDetails(row).length);
	}

	function visibleAttributeRows(attribute: { rows: TraceRow[] }) {
		return attribute.rows.filter(rowHasDetails);
	}

	function attributeHasDetails(attribute: { label: string; rows: TraceRow[] }) {
		return Boolean(attributeFullValue(attribute) || visibleAttributeRows(attribute).length);
	}

	function attributeChangeTags(rows: TraceRow[]) {
		const tags = new Set<string>();
		for (const row of rows) {
			const change = attributeChange(row);
			if (!change || !row.previousOwner) continue;
			tags.add(`${change} ${ownerType(row.previousOwner)}`);
		}
		return [...tags];
	}

	function attributeChange(row: AttributeTrace) {
		if (!row.previousOwner) return '';
		if (row.status === 'deletes') return 'replaces';
		if (row.status === 'overrides') return 'overrides';
		if (Array.isArray(row.previousValue) && Array.isArray(row.value)) return 'extends';
		if (!sameTraceValue(row.previousValue, row.value)) return 'replaces';
		return '';
	}

	function compactPolicyRows(rows: TraceRow[]) {
		const normalized = rows.map((row) => ({
			...row,
			displayPath: normalizePolicyDisplayPath(row.displayPath)
		}));
		return normalized.filter((row) => {
			if (row.path.endsWith('.schema.type')) {
				return !normalized.some(
					(candidate) =>
						candidate !== row &&
						candidate.displayPath === 'type' &&
						!candidate.path.endsWith('.schema.type') &&
						sameTraceValue(candidate.value, row.value)
				);
			}
			if (row.path.endsWith('.schema.enum')) {
				return !normalized.some(
					(candidate) =>
						candidate.displayPath === 'values' && sameTraceValue(candidate.value, row.value)
				);
			}
			return true;
		});
	}

	function normalizePolicyDisplayPath(path: string) {
		return path.startsWith('schema.') ? path.slice('schema.'.length) : path;
	}

	function unique<T>(items: T[]) {
		return [...new Set(items)];
	}

	function sameTraceValue(left: unknown, right: unknown) {
		return JSON.stringify(left) === JSON.stringify(right);
	}

	function tracePlacement(path: string, policyKeys: string[]) {
		for (const key of policyKeys) {
			if (path !== key && !path.startsWith(`${key}.`)) continue;
			const [, sectionKey, ...nameParts] = key.split('.');
			if (sectionKey === 'headers' || sectionKey === 'parameters') {
				return {
					sectionKey: 'schema',
					subsectionKey: sectionKey,
					attributeKey: nameParts.join('.'),
					displayPath: path === key ? '' : path.slice(key.length + 1)
				};
			}
			return {
				sectionKey,
				attributeKey: nameParts.join('.'),
				displayPath: path === key ? '' : path.slice(key.length + 1)
			};
		}
		const parts = path.split('.');
		if (parts[0] === 'schema' && (parts[1] === 'headers' || parts[1] === 'parameters')) {
			return {
				sectionKey: 'schema',
				subsectionKey: parts[1],
				attributeKey: parts[2] ?? parts[1],
				displayPath: parts.length > 3 ? parts.slice(3).join('.') : ''
			};
		}
		return {
			sectionKey: parts.length > 1 ? parts[0] : 'attributes',
			attributeKey: parts.length > 1 ? parts[1] : parts[0],
			displayPath: parts.length > 2 ? parts.slice(2).join('.') : ''
		};
	}

	function groupLabel(value: string) {
		const labels: Record<string, string> = {
			attributes: 'Attributes',
			headers: 'Headers',
			parameters: 'Parameters',
			pricing: 'Pricing',
			policy: 'Policy',
			schema: 'Schema'
		};
		return labels[value] ?? attributeLabel(value);
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

	function ownerType(owner: string) {
		return owner.split(':', 1)[0] || 'stogasEndpoint';
	}

	function ownerLabel(owner: string) {
		const id = ownerId(owner);
		return id ? `${ownerType(owner)} / ${id}` : ownerType(owner);
	}

	function ownerTypeLabel(owner: string) {
		return attributeLabel(ownerType(owner));
	}

	function ownerColor(owner: string) {
		return (
			{
				stogasEndpoint: '#0f766e',
				author: '#0ea5e9',
				model: '#166534',
				provider: '#f59e0b',
				providerEndpoint: '#7c3aed',
				deployment: '#e11d48',
				location: '#475569'
			}[ownerType(owner)] ?? '#475569'
		);
	}

	function showChainNode(node: { type: NodeType }) {
		return true;
	}

	function dedupedVisibleLineage(nodes: LineageNode[]) {
		const seen = new Set<string>();
		const visible: LineageNode[] = [];
		for (const node of nodes) {
			if (!showChainNode(node)) continue;
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

		{#if false}
		<section class="trace">
			<div class="section-head trace-title">
				<div>
					<span>Attributes</span>
					<strong>{attributeScope === 'selected' ? 'This node' : 'Resolved chain'}</strong>
				</div>
				<small>{traces.length} rows</small>
			</div>
			<div class="trace-head">
				<div class="segmented" aria-label="Attribute display mode">
					<button
						type="button"
						class:active={attributeScope === 'selected'}
						onclick={() => (attributeScope = 'selected')}>This node</button
					>
					<button
						type="button"
						class:active={attributeScope === 'inherited'}
						onclick={() => (attributeScope = 'inherited')}>Resolved chain</button
					>
				</div>
				<input bind:value={traceFilter} placeholder="Search" aria-label="Search attributes" />
			</div>

			{#if attributeScope === 'inherited'}
				<div class="trace-tools">
					<select bind:value={ownerFilter} aria-label="Filter attributes by owner">
						<option value="all">All nodes</option>
						{#each ownerOptions as owner (owner)}
							<option value={owner}>{owner}</option>
						{/each}
					</select>
					<label class="check">
						<input type="checkbox" bind:checked={overrideOnly} />
						overrides
					</label>
				</div>
			{/if}

			<div class="trace-list">
				{#if !hasTraceGroups}
					<p class="empty">No matching attributes.</p>
				{/if}
				{#if directAttributes.length}
					<div class="direct-attributes" aria-label="Direct attributes">
						{#each directAttributes as attribute (attribute.key)}
							{@const full = attributeFullValue(attribute)}
							<svelte:element
								this={attributeHasDetails(attribute) ? 'details' : 'div'}
								class="attribute-card"
								class:attribute-card-static={!attributeHasDetails(attribute)}
							>
								<svelte:element
									this={attributeHasDetails(attribute) ? 'summary' : 'div'}
									class="attribute-summary"
								>
									<span class="attribute-title">
										<span class="trace-summary-label">{attribute.label}</span>
										<span class="attribute-preview">{attribute.preview}</span>
									</span>
									<span class="attribute-summary-meta">
										{#if attribute.rows.length > 1}
											<span class="meta-tag">{attribute.rows.length} fields</span>
										{/if}
										{#each attribute.owners as owner (owner)}
											<span
												class="node-tag"
												data-type={ownerType(owner)}
												style:--owner-color={ownerColor(owner)}
												title={ownerLabel(owner)}>{ownerTypeLabel(owner)}</span
											>
										{/each}
										{#each attribute.changeTags as tag (tag)}
											<span class="status-tag" data-status={tag.split(' ', 1)[0]}>{tag}</span>
										{/each}
									</span>
								</svelte:element>
								{#if full}
									<div class="attribute-full-value">
										<details class="value-details">
											<summary>Full value</summary>
											<pre>{displayValue(full.value)}</pre>
										</details>
									</div>
								{/if}
								{#each visibleAttributeRows(attribute) as trace (trace.owner + ':' + trace.path)}
									{#if rowHasDetails(trace)}
										<details
											class="attribute-row"
											class:override={trace.status === 'overrides'}
											class:delete={trace.status === 'deletes'}
											data-owner={ownerType(trace.owner)}
											style:--owner-color={ownerColor(trace.owner)}
											title={traceTitle(trace)}
										>
											<summary class="attribute-row-summary">
												<span class="row-path">{trace.displayPath || attribute.label}</span>
												<span class="row-value-preview">{valuePreview(trace.value)}</span>
											</summary>
											<div class="attribute-row-body">
												{#if trace.previousOwner}
													<div class="row-change-line">
														<span>{attributeChange(trace) || 'replaces'}</span>
														<strong>{ownerLabel(trace.previousOwner)}</strong>
													</div>
												{/if}
												{#each policyDetails(trace) as policy (`${trace.path}:${policy.name}:${displayValue(policy.value)}`)}
													<div class="trait-row">
														<span>{displayRuleName(policy.name)}</span>
														<code>{displayRuleValue(policy.value)}</code>
													</div>
												{/each}
											</div>
										</details>
									{:else}
										<div class="attribute-row attribute-row-static">
											<div class="attribute-row-summary">
												<span class="row-path">{trace.displayPath || attribute.label}</span>
												<span class="row-value-preview">{valuePreview(trace.value)}</span>
											</div>
										</div>
									{/if}
								{/each}
							</svelte:element>
						{/each}
					</div>
				{/if}

				{#each sectionedTraceGroups as section (section.key)}
					<details class="trace-section" open>
						<summary>
							<span>{section.label}</span>
							<small>{traceSectionCount(section)}</small>
						</summary>
						{#each section.attributes as attribute (attribute.key)}
							{@const full = attributeFullValue(attribute)}
							<svelte:element
								this={attributeHasDetails(attribute) ? 'details' : 'div'}
								class="attribute-card"
								class:attribute-card-static={!attributeHasDetails(attribute)}
							>
								<svelte:element
									this={attributeHasDetails(attribute) ? 'summary' : 'div'}
									class="attribute-summary"
								>
									<span class="attribute-title">
										<span class="trace-summary-label">{attribute.label}</span>
										<span class="attribute-preview">{attribute.preview}</span>
									</span>
									<span class="attribute-summary-meta">
										{#if attribute.rows.length > 1}
											<span class="meta-tag">{attribute.rows.length} fields</span>
										{/if}
										{#each attribute.owners as owner (owner)}
											<span
												class="node-tag"
												data-type={ownerType(owner)}
												style:--owner-color={ownerColor(owner)}
												title={ownerLabel(owner)}>{ownerTypeLabel(owner)}</span
											>
										{/each}
										{#each attribute.changeTags as tag (tag)}
											<span class="status-tag" data-status={tag.split(' ', 1)[0]}>{tag}</span>
										{/each}
									</span>
								</svelte:element>
								{#if full}
									<div class="attribute-full-value">
										<details class="value-details">
											<summary>Full value</summary>
											<pre>{displayValue(full.value)}</pre>
										</details>
									</div>
								{/if}
								{#each visibleAttributeRows(attribute) as trace (trace.owner + ':' + trace.path)}
									{#if rowHasDetails(trace)}
										<details
											class="attribute-row"
											class:override={trace.status === 'overrides'}
											class:delete={trace.status === 'deletes'}
											data-owner={ownerType(trace.owner)}
											style:--owner-color={ownerColor(trace.owner)}
											title={traceTitle(trace)}
										>
											<summary class="attribute-row-summary">
												<span class="row-path">{trace.displayPath || attribute.label}</span>
												<span class="row-value-preview">{valuePreview(trace.value)}</span>
											</summary>
											<div class="attribute-row-body">
												{#if trace.previousOwner}
													<div class="row-change-line">
														<span>{attributeChange(trace) || 'replaces'}</span>
														<strong>{ownerLabel(trace.previousOwner)}</strong>
													</div>
												{/if}
												{#each policyDetails(trace) as policy (`${trace.path}:${policy.name}:${displayValue(policy.value)}`)}
													<div class="trait-row">
														<span>{displayRuleName(policy.name)}</span>
														<code>{displayRuleValue(policy.value)}</code>
													</div>
												{/each}
											</div>
										</details>
									{:else}
										<div class="attribute-row attribute-row-static">
											<div class="attribute-row-summary">
												<span class="row-path">{trace.displayPath || attribute.label}</span>
												<span class="row-value-preview">{valuePreview(trace.value)}</span>
											</div>
										</div>
									{/if}
								{/each}
							</svelte:element>
						{/each}
						{#each section.subsections as subsection (subsection.key)}
							<details class="trace-subsection" open>
								<summary>
									<span>{subsection.label}</span>
									<small>{subsection.attributes.length}</small>
								</summary>
								{#each subsection.attributes as attribute (attribute.key)}
									{@const full = attributeFullValue(attribute)}
									<svelte:element
										this={attributeHasDetails(attribute) ? 'details' : 'div'}
										class="attribute-card"
										class:attribute-card-static={!attributeHasDetails(attribute)}
									>
										<svelte:element
											this={attributeHasDetails(attribute) ? 'summary' : 'div'}
											class="attribute-summary"
										>
											<span class="attribute-title">
												<span class="trace-summary-label">{attribute.label}</span>
												<span class="attribute-preview">{attribute.preview}</span>
											</span>
											<span class="attribute-summary-meta">
												{#if attribute.rows.length > 1}
													<span class="meta-tag">{attribute.rows.length} fields</span>
												{/if}
												{#each attribute.owners as owner (owner)}
													<span
														class="node-tag"
														data-type={ownerType(owner)}
														style:--owner-color={ownerColor(owner)}
														title={ownerLabel(owner)}>{ownerTypeLabel(owner)}</span
													>
												{/each}
												{#each attribute.changeTags as tag (tag)}
													<span class="status-tag" data-status={tag.split(' ', 1)[0]}>{tag}</span>
												{/each}
											</span>
										</svelte:element>
										{#if full}
											<div class="attribute-full-value">
												<details class="value-details">
													<summary>Full value</summary>
													<pre>{displayValue(full.value)}</pre>
												</details>
											</div>
										{/if}
										{#each visibleAttributeRows(attribute) as trace (trace.owner + ':' + trace.path)}
											<details
												class="attribute-row"
												class:override={trace.status === 'overrides'}
												class:delete={trace.status === 'deletes'}
												data-owner={ownerType(trace.owner)}
												style:--owner-color={ownerColor(trace.owner)}
												title={traceTitle(trace)}
											>
												<summary class="attribute-row-summary">
													<span class="row-path">{trace.displayPath || attribute.label}</span>
													<span class="row-value-preview">{valuePreview(trace.value)}</span>
												</summary>
												<div class="attribute-row-body">
													{#if trace.previousOwner}
														<div class="row-change-line">
															<span>{attributeChange(trace) || 'replaces'}</span>
															<strong>{ownerLabel(trace.previousOwner)}</strong>
														</div>
													{/if}
													{#each policyDetails(trace) as policy (`${trace.path}:${policy.name}:${displayValue(policy.value)}`)}
														<div class="trait-row">
															<span>{displayRuleName(policy.name)}</span>
															<code>{displayRuleValue(policy.value)}</code>
														</div>
													{/each}
												</div>
											</details>
										{/each}
									</svelte:element>
								{/each}
							</details>
						{/each}
					</details>
				{/each}
			</div>
		</section>
		{/if}
	</aside>
</main>
