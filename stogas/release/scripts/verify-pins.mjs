#!/usr/bin/env node
// Checks release pins that the Guix build cannot check by itself.
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const read = (path) => readFileSync(resolve(repoRoot, path), 'utf8');
const pins = JSON.parse(read('stogas/release/pins.lock.json')).releaseSources;
const failures = [];
const check = (condition, message) => condition || failures.push(message);

// Without a full commit, guix time-machine follows the channel branch.
check(
	/\(commit "[0-9a-f]{40}"\)/.test(read('stogas/release/guix/channels.scm')),
	'stogas/release/guix/channels.scm must pin a full Guix commit.'
);

// Gateway tests must use the release compiler, and the Go bindings must match
// the Rust verifier library that the release links.
const goMod = read('transports/go.mod');
// Go drops a toolchain line that repeats the go line, which then names the toolchain.
const toolchain = goMod.match(/^toolchain go(\S+)$/m)?.[1] ?? goMod.match(/^go (\S+)$/m)?.[1];
check(
	toolchain === pins.go.version,
	`transports/go.mod must use the release toolchain go${pins.go.version}.`
);
const required = new Map(
	[...goMod.matchAll(/^\s*(\S+) (v\S+)$/gm)].map(([, module, version]) => [module, version])
);
for (const module of ['github.com/StogasAI/stogas/go', 'github.com/StogasAI/stogas/go/reference']) {
	check(
		required.get(module)?.endsWith(`-${pins.stogasVerifier.commit.slice(0, 12)}`),
		`${module} must use the pinned verifier commit ${pins.stogasVerifier.commit}.`
	);
}

// A tag or branch can move; a full commit cannot. A local action named with $/ runs from the
// workflow's own commit, while ./ runs whatever the job checked out.
const workflowFiles = ['.github/workflows', '.github/actions'].flatMap((directory) =>
	readdirSync(resolve(repoRoot, directory), { recursive: true })
		.filter((file) => /\.ya?ml$/.test(file))
		.map((file) => join(directory, file))
);
for (const file of workflowFiles) {
	for (const [, action] of read(file).matchAll(/^[\s-]*uses:\s*['"]?([^\s'"#]+)/gm)) {
		check(
			action.startsWith('$/') || /^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/.test(action),
			`${file} must pin ${action} to a full commit, or name a local action with $/.`
		);
	}
}

if (failures.length > 0) {
	console.error(failures.join('\n'));
	process.exit(1);
}
