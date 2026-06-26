import { spawn } from 'node:child_process';
import {
	existsSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync
} from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const root = fileURLToPath(new URL('..', import.meta.url)).replace(/\/$/, '');
const compiledDir = join(root, '..', 'generated');
const jsonPath = join(compiledDir, 'catalog.json');
const gzipPath = join(compiledDir, 'catalog.json.gz');
const tempBuildDir = join(root, '.tmp-catalog-build');
const cueVersion = 'v0.16.1';
const toolCacheDir = join(resolveToolCacheRoot(), 'cue', cueVersion);
const cachedCue = join(toolCacheDir, process.platform === 'win32' ? 'cue.exe' : 'cue');
const args = new Set(process.argv.slice(2));

function resolveToolCacheRoot() {
	const configured = process.env.STOGAS_CATALOG_TOOL_CACHE_DIR?.trim();
	if (configured) return configured;
	const xdgCache = process.env.XDG_CACHE_HOME?.trim();
	if (xdgCache) return join(xdgCache, 'stogas', 'catalog-tools');
	const home = homedir();
	if (home) return join(home, '.cache', 'stogas', 'catalog-tools');
	throw new Error(
		'Unable to resolve CUE tool cache directory. Set STOGAS_CATALOG_TOOL_CACHE_DIR or HOME.'
	);
}

function walkFiles(dir, predicate) {
	const files = [];
	for (const entry of readdirSync(dir).sort()) {
		const path = join(dir, entry);
		const stats = statSync(path);
		if (stats.isDirectory()) {
			files.push(...walkFiles(path, predicate));
		} else if (predicate(path)) {
			files.push(path);
		}
	}
	return files;
}

function rel(path) {
	return relative(root, path);
}

function fileOwnedNodeSource(path) {
	if (!/\.ya?ml$/.test(path)) return null;
	const type = fileOwnedNodeType(path);
	if (!type) return null;
	return { type, id: basename(path).replace(/\.ya?ml$/, '') };
}

function fileOwnedNodeType(path) {
	const content = readFileSync(path, 'utf8').replace(/^\uFEFF/, '');
	const body = content.replace(/^---[ \t]*(?:\r?\n|$)/, '');
	const match =
		/^(authors|deployments|models|providerEndpoints|providers|stogasEndpoints):\s*$/m.exec(body);
	return match?.[1] ?? null;
}

function fileOwnedNodeBody(path, source) {
	const content = readFileSync(path, 'utf8').replace(/^\uFEFF/, '');
	const body = content.replace(/^---[ \t]*(?:\r?\n|$)/, '').trimEnd();
	const lines = body.split(/\r?\n/);
	const firstContentIndex = lines.findIndex((line) => line.trim() && !line.trim().startsWith('#'));
	if (firstContentIndex === -1 || lines[firstContentIndex].trim() !== `${source.type}:`) {
		throw new Error(
			`${rel(path)} must declare ${source.type} as the file-owned node type container`
		);
	}
	const nested = lines.slice(firstContentIndex + 1);
	for (const line of nested) {
		if (line.trim() && !line.startsWith('  ')) {
			throw new Error(`${rel(path)} has content outside the ${source.type} node type container`);
		}
	}
	const nodeBody = nested.map((line) => (line.startsWith('  ') ? line.slice(2) : line)).join('\n');
	const firstNodeLine = nodeBody.split(/\r?\n/).find((line) => line.trim());
	if (firstNodeLine?.trim() === `${source.id}:`) {
		throw new Error(
			`${rel(path)} must not wrap itself in ${source.type}.${source.id}; the file path already owns the node id`
		);
	}
	return nodeBody;
}

function indentYaml(content, spaces) {
	const prefix = ' '.repeat(spaces);
	return content
		.split(/\r?\n/)
		.map((line) => (line.trim() ? `${prefix}${line}` : line))
		.join('\n');
}

function writeFileOwnedNodeSource(sources) {
	if (!sources.length) return null;
	mkdirSync(tempBuildDir, { recursive: true });
	const grouped = new Map();
	for (const source of sources) {
		const entries = grouped.get(source.type) ?? [];
		entries.push(source);
		grouped.set(source.type, entries);
	}
	const content = [...grouped.entries()]
		.sort(([left], [right]) => left.localeCompare(right))
		.flatMap(([type, entries]) => [
			`${type}:`,
			...entries
				.sort((left, right) => left.id.localeCompare(right.id))
				.flatMap((source) => [
					`  ${source.id}:`,
					indentYaml(fileOwnedNodeBody(source.path, source), 4)
				])
		])
		.join('\n');
	const generatedPath = join(tempBuildDir, 'file-owned-nodes.yaml');
	writeFileSync(generatedPath, `${content.trimEnd()}\n`);
	return generatedPath;
}

function run(command, options = {}) {
	return new Promise((resolve, reject) => {
		const child = spawn(command[0], command.slice(1), {
			cwd: root,
			env: { ...process.env, ...options.env },
			stdio: ['ignore', 'pipe', 'pipe']
		});

		let stdout = '';
		let stderr = '';
		child.stdout.setEncoding('utf8');
		child.stderr.setEncoding('utf8');
		child.stdout.on('data', (chunk) => {
			stdout += chunk;
		});
		child.stderr.on('data', (chunk) => {
			stderr += chunk;
		});
		child.on('error', reject);
		child.on('close', (code) => {
			if (code === 0) {
				resolve(stdout);
				return;
			}
			reject(new Error(`${command.join(' ')} failed\n${stderr || stdout}`));
		});
	});
}

async function commandWorks(command) {
	try {
		await run(command);
		return true;
	} catch {
		return false;
	}
}

async function resolveCueCommand() {
	const configured = process.env.CUE_BIN?.trim();
	if (configured) return configured.split(/\s+/);
	if (existsSync(cachedCue) && (await commandWorks([cachedCue, 'version']))) return [cachedCue];
	if (await commandWorks(['cue', 'version'])) return ['cue'];
	if (await commandWorks(['go', 'version'])) {
		mkdirSync(toolCacheDir, { recursive: true });
		await run(['go', 'install', `cuelang.org/go/cmd/cue@${cueVersion}`], {
			env: { GOBIN: toolCacheDir }
		});
		return [cachedCue];
	}
	throw new Error(
		'CUE is required. Install cue, install Go, or set CUE_BIN to a compatible cue command.'
	);
}

function writeIfChanged(path, content) {
	if (existsSync(path)) {
		const existing = readFileSync(path);
		const next = typeof content === 'string' ? Buffer.from(content) : Buffer.from(content);
		if (existing.equals(next)) return;
	}
	writeFileSync(path, content);
}

function validateCatalogReferences(catalog) {
	const graph = catalog?.graph;
	if (!graph?.stogasEndpoints) return;
	for (const [providerEndpointId, providerEndpoint] of Object.entries(
		graph.providerEndpoints ?? {}
	)) {
		for (const stogasEndpointId of providerEndpoint.stogasEndpoints ?? []) {
			if (!graph.stogasEndpoints[stogasEndpointId]) {
				throw new Error(`${providerEndpointId}: missing stogas endpoint ${stogasEndpointId}`);
			}
		}
	}
}

function applyCompiledDerivations(catalog) {
	applyGraphDerivations(catalog);
	rebuildIndexes(catalog);
}

function applyGraphDerivations(catalog) {
	const graph = catalog?.graph;
	if (!graph?.providerEndpoints) return;
	for (const [endpointId, endpoint] of Object.entries(graph.providerEndpoints)) {
		endpoint.deploymentIds = deploymentIdsForProviderEndpoint(graph, endpointId);
	}
}

function enumeratedPublicModelSlugs(graph, deployment) {
	const model = graph.models?.[deployment.modelId];
	const authorSlugs = graph.authors?.[model?.authorId]?.authorSlugs ?? [];
	const providerSlugs = graph.providers?.[deployment.providerId]?.providerSlugs ?? [];
	const aliasSlugs = deployment.aliasSlugs ?? [];
	const slugs = [];
	for (const alias of aliasSlugs) {
		slugs.push(alias);
		for (const provider of providerSlugs) slugs.push(`${provider}/${alias}`);
		for (const author of authorSlugs) {
			slugs.push(`${author}/${alias}`);
			for (const provider of providerSlugs) slugs.push(`${author}/${provider}/${alias}`);
		}
	}
	return slugs;
}

function rebuildIndexes(catalog) {
	const graph = catalog?.graph;
	if (!graph) return;
	catalog.indexes = {
		author_slugs: slugIndex(graph.authors, (author) => [...(author.authorSlugs ?? [])]),
		provider_slugs: slugIndex(graph.providers, (provider) => [...(provider.providerSlugs ?? [])]),
		provider_endpoint_request_slugs: providerEndpointRequestSlugs(graph),
		provider_endpoint_deployments: providerEndpointDeployments(graph),
		stogas_endpoint_provider_endpoints: stogasEndpointProviderEndpoints(graph)
	};
}

function slugIndex(nodes, slugsForNode) {
	const index = {};
	for (const [id, node] of Object.entries(nodes ?? {})) {
		for (const slug of slugsForNode(node)) {
			if (typeof slug === 'string' && slug) index[slug] = id;
		}
	}
	return index;
}

function providerEndpointRequestSlugs(graph) {
	const index = {};
	for (const [endpointId] of Object.entries(graph.providerEndpoints ?? {})) {
		for (const deploymentId of deploymentIdsForProviderEndpoint(graph, endpointId)) {
			const deployment = graph.deployments?.[deploymentId];
			if (!deployment) continue;
			for (const slug of enumeratedPublicModelSlugs(graph, deployment)) {
				if (typeof slug === 'string' && slug) {
					index[`${endpointId}:${slug}`] = deploymentId;
				}
			}
		}
	}
	return index;
}

function providerEndpointDeployments(graph) {
	return Object.fromEntries(
		Object.keys(graph.providerEndpoints ?? {}).map((endpointId) => [
			endpointId,
			deploymentIdsForProviderEndpoint(graph, endpointId)
		])
	);
}

function deploymentIdsForProviderEndpoint(graph, endpointId) {
	return Object.entries(graph.deployments ?? {})
		.filter(([, deployment]) => deployment.parentProviderEndpointNodes?.includes(endpointId))
		.map(([deploymentId]) => deploymentId)
		.sort((a, b) => deploymentSortKey(a).localeCompare(deploymentSortKey(b)));
}

function deploymentSortKey(deploymentId) {
	const tierRank = deploymentId.endsWith('-priority')
		? '2'
		: deploymentId.endsWith('-flex')
			? '1'
			: '0';
	const base = deploymentId.replace(/-(flex|priority)$/, '');
	const familyRank = base.startsWith('gpt-5.5')
		? '0'
		: base.startsWith('gpt-5-nano')
			? '1'
			: base.startsWith('gpt-5-search-api')
				? '2'
				: base.startsWith('gpt-4o-search-preview')
					? '3'
					: base.startsWith('gpt-4o-mini-search-preview')
						? '4'
						: '9';
	return `${familyRank}:${base}:${tierRank}:${deploymentId}`;
}

function stogasEndpointProviderEndpoints(graph) {
	const index = {};
	for (const stogasEndpointId of Object.keys(graph.stogasEndpoints ?? {})) {
		index[stogasEndpointId] = Object.entries(graph.providerEndpoints ?? {})
			.filter(([, endpoint]) => endpoint.stogasEndpoints?.includes(stogasEndpointId))
			.map(([endpointId]) => endpointId);
	}
	return index;
}

function unique(items) {
	return [...new Set(items)];
}

if (args.has('--clean')) {
	rmSync(compiledDir, { force: true, recursive: true });
	rmSync(tempBuildDir, { force: true, recursive: true });
	process.exit(0);
}

const cueFiles = walkFiles(join(root, 'cue'), (path) => path.endsWith('.cue')).map(rel);
const allDataFiles = walkFiles(
	join(root, 'data'),
	(path) => path.endsWith('.yaml') || path.endsWith('.yml')
);
const fileOwnedSources = allDataFiles
	.map((path) => ({ path, source: fileOwnedNodeSource(path) }))
	.filter(({ source }) => source)
	.map(({ path, source }) => ({ ...source, path }));
const fileOwnedPaths = new Set(fileOwnedSources.map((source) => source.path));
const dataFiles = allDataFiles.filter((path) => !fileOwnedPaths.has(path)).map(rel);

rmSync(tempBuildDir, { force: true, recursive: true });
const generatedFileOwnedSource = writeFileOwnedNodeSource(fileOwnedSources);

try {
	const cue = await resolveCueCommand();
	const sourceFiles = [
		...cueFiles,
		...dataFiles,
		...(generatedFileOwnedSource ? [rel(generatedFileOwnedSource)] : [])
	];

	const exported = await run([...cue, 'export', ...sourceFiles, '-e', 'compiled', '--out', 'json']);
	const catalog = JSON.parse(exported);
	applyCompiledDerivations(catalog);
	validateCatalogReferences(catalog);

	if (!args.has('--validate-only')) {
		const minified = `${JSON.stringify(catalog)}\n`;
		const gzipped = gzipSync(minified, { level: 9, mtime: 0 });

		if (args.has('--check')) {
			const currentJson = existsSync(jsonPath) ? readFileSync(jsonPath, 'utf8') : null;
			const currentGzip = existsSync(gzipPath) ? readFileSync(gzipPath) : null;
			if (currentJson !== minified || !currentGzip?.equals(gzipped)) {
				throw new Error(
					'Compiled catalog artifacts are stale. Run `npm run build` or `bun run build`.'
				);
			}
		} else {
			mkdirSync(compiledDir, { recursive: true });
			writeIfChanged(jsonPath, minified);
			writeIfChanged(gzipPath, gzipped);
		}
	}
} finally {
	rmSync(tempBuildDir, { force: true, recursive: true });
}
