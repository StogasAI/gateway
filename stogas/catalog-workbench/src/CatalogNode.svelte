<script lang="ts">
	import { Handle, Position, type NodeProps } from '@xyflow/svelte';
	import type { GraphNodeData } from './types';

	let { data }: NodeProps & { data: GraphNodeData } = $props();
</script>

{#if data.handles?.leftIn}
	<Handle id="left-in" type="target" position={Position.Left} />
{/if}
{#if data.handles?.leftOut}
	<Handle id="left-out" type="source" position={Position.Left} />
{/if}

<div class="node-card">
	<strong>{data.id}</strong>
</div>

{#if data.handles?.rightIn}
	<Handle id="right-in" type="target" position={Position.Right} />
{/if}
{#if data.handles?.rightOut}
	<Handle id="right-out" type="source" position={Position.Right} />
{/if}
