<script lang="ts">
	import { Handle, Position, type NodeProps } from '@xyflow/svelte';
	import type { GraphNodeData } from './types';

	let { data }: NodeProps & { data: GraphNodeData } = $props();
</script>

{#if data.handles?.leftIn}
	<Handle id="left-in" class="catalog-flow-handle" type="target" position={Position.Left} />
{/if}
{#if data.handles?.leftOut}
	<Handle id="left-out" class="catalog-flow-handle" type="source" position={Position.Left} />
{/if}

<div class="node-card">
	<strong>{data.label}</strong>
	{#if data.subtitle}
		<span>{data.subtitle}</span>
	{/if}
</div>

{#if data.handles?.rightIn}
	<Handle id="right-in" class="catalog-flow-handle" type="target" position={Position.Right} />
{/if}
{#if data.handles?.rightOut}
	<Handle id="right-out" class="catalog-flow-handle" type="source" position={Position.Right} />
{/if}
