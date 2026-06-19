import { spawn } from 'node:child_process';
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig, type Plugin } from 'vite';

const editorRoot = dirname(fileURLToPath(import.meta.url));
const catalogRoot = resolve(editorRoot, '../../transports/stogas/catalog/source');
const dataRoot = join(catalogRoot, 'data');
const yamlPattern = /\.(ya?ml)$/;

export default defineConfig({
	root: editorRoot,
	plugins: [catalogApi(), svelte()],
	server: {
		port: 5177,
		strictPort: false
	}
});

function catalogApi(): Plugin {
	return {
		name: 'stogas-catalog-api',
		configureServer(server) {
			server.middlewares.use('/api/catalog/sources', async (_req, res) => {
				sendJson(res, readSources());
			});
			server.middlewares.use('/api/catalog/source', async (req, res) => {
				if (req.method !== 'PUT') {
					sendJson(res, { error: 'Method not allowed' }, 405);
					return;
				}
				const body = await readBody(req);
				const { path, content } = JSON.parse(body || '{}') as { path?: string; content?: string };
				if (!path || typeof content !== 'string' || !yamlPattern.test(path)) {
					sendJson(res, { error: 'Expected YAML path and content' }, 400);
					return;
				}
				const absolute = safeCatalogPath(path);
				if (!absolute) {
					sendJson(res, { error: 'Path escapes catalog root' }, 400);
					return;
				}
				writeFileSync(absolute, content);
				sendJson(res, { ok: true });
			});
			server.middlewares.use('/api/catalog/build', async (req, res) => {
				if (req.method !== 'POST') {
					sendJson(res, { error: 'Method not allowed' }, 405);
					return;
				}
				try {
					const output = await run([process.execPath, 'scripts/build.mjs'], catalogRoot);
					sendJson(res, { ok: true, output });
				} catch (error) {
					sendJson(
						res,
						{ ok: false, output: error instanceof Error ? error.message : String(error) },
						500
					);
				}
			});
		}
	};
}

function readSources() {
	const files = walk(dataRoot)
		.filter((path) => yamlPattern.test(path))
		.map((path) => ({
			path: relative(catalogRoot, path),
			content: readFileSync(path, 'utf8')
		}));
	const nodeSources: Record<string, string[]> = {};
	for (const file of files) {
		indexNodeSources(file.path, file.content, nodeSources);
	}
	return { files, nodeSources };
}

function walk(dir: string): string[] {
	return readdirSync(dir)
		.flatMap((entry) => {
			const path = join(dir, entry);
			return statSync(path).isDirectory() ? walk(path) : [path];
		})
		.sort();
}

function indexNodeSources(path: string, content: string, nodeSources: Record<string, string[]>) {
	const fileOwned = fileOwnedNodeSource(path);
	if (fileOwned) {
		pushSource(nodeSources, `${fileOwned.type}:${fileOwned.id}`, path);
		return;
	}
	if (path === 'data/locations.yaml') {
		for (const match of content.matchAll(/^ {4}([a-z0-9][a-z0-9._:-]*):$/gm)) {
			pushSource(nodeSources, `location:${match[1]}`, path);
		}
		return;
	}
	const sectionTypes: Record<string, string> = {
		authors: 'author',
		deployments: 'deployment',
		models: 'model',
		providers: 'provider',
		providerEndpoints: 'providerEndpoint',
		stogasEndpoints: 'stogasEndpoint'
	};
	let section = '';
	for (const line of content.split('\n')) {
		const top = /^([a-z]+):$/.exec(line);
		if (top) section = top[1];
		const node = /^ {2}([a-z0-9][a-z0-9._:-]*):$/.exec(line);
		if (node && sectionTypes[section])
			pushSource(nodeSources, `${sectionTypes[section]}:${node[1]}`, path);
	}
}

function fileOwnedNodeSource(path: string) {
	if (!yamlPattern.test(path)) return null;
	const content = readFileSync(join(catalogRoot, path), 'utf8')
		.replace(/^\uFEFF/, '')
		.replace(/^---[ \t]*(?:\r?\n|$)/, '');
	const match =
		/^(authors|deployments|models|providers|providerEndpoints|stogasEndpoints):\s*$/m.exec(content);
	if (!match) return null;
	const type = singularNodeType(match[1]);
	return { type, id: basename(path).replace(/\.ya?ml$/, '') };
}

function singularNodeType(type: string) {
	const types: Record<string, string> = {
		authors: 'author',
		deployments: 'deployment',
		models: 'model',
		providers: 'provider',
		providerEndpoints: 'providerEndpoint',
		stogasEndpoints: 'stogasEndpoint'
	};
	return types[type];
}

function pushSource(nodeSources: Record<string, string[]>, key: string, path: string) {
	nodeSources[key] = [...(nodeSources[key] ?? []), path];
}

function safeCatalogPath(path: string) {
	const absolute = resolve(catalogRoot, path);
	const root = `${catalogRoot}${sep}`;
	return absolute.startsWith(root) ? absolute : null;
}

function readBody(req: import('node:http').IncomingMessage) {
	return new Promise<string>((resolveBody, reject) => {
		let body = '';
		req.setEncoding('utf8');
		req.on('data', (chunk) => (body += chunk));
		req.on('end', () => resolveBody(body));
		req.on('error', reject);
	});
}

function run(command: string[], cwd = catalogRoot) {
	return new Promise<string>((resolveRun, reject) => {
		const child = spawn(command[0], command.slice(1), { cwd });
		let output = '';
		child.stdout.setEncoding('utf8');
		child.stderr.setEncoding('utf8');
		child.stdout.on('data', (chunk) => (output += chunk));
		child.stderr.on('data', (chunk) => (output += chunk));
		child.on('error', reject);
		child.on('close', (code) => {
			if (code === 0) resolveRun(output.trim());
			else reject(new Error(output.trim()));
		});
	});
}

function sendJson(res: import('node:http').ServerResponse, value: unknown, status = 200) {
	res.statusCode = status;
	res.setHeader('content-type', 'application/json');
	res.end(JSON.stringify(value));
}
