#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const releaseRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(releaseRoot, '../..');
const pinsPath = resolve(releaseRoot, 'pins.lock.json');
const pins = JSON.parse(readFileSync(pinsPath, 'utf8'));

const workflowPaths = [
	resolve(repoRoot, '.github/workflows/gateway-igvm-release.yml'),
	resolve(repoRoot, '.github/workflows/pr-dependencies.yml')
];
const releaseSchemePaths = [
	resolve(releaseRoot, 'guix/release.scm'),
	resolve(releaseRoot, 'guix/modules/stogas/release/packages.scm')
];

function assert(condition, message) {
	if (!condition) throw new Error(message);
}

function assertSha256(value, label) {
	assert(/^[a-f0-9]{64}$/.test(value), `${label} must be a lowercase SHA-256 digest.`);
}

function assertBase32(value, label) {
	assert(/^[a-z0-9]{52}$/.test(value), `${label} must be a Guix base32 digest.`);
}

function assertCommit(value, label) {
	assert(/^[a-f0-9]{40}$/.test(value), `${label} must be a full lowercase Git commit.`);
}

function verifyLockShape() {
	assert(pins.schema === 'stogas.gateway.release.pins.v1', 'Unsupported release pin schema.');
	assertSha256(pins.guix.bootstrapBinary.sha256, 'Guix bootstrap binary hash');
	assertCommit(pins.guix.channel.commit, 'Guix channel commit');
	assertCommit(pins.guix.channel.introductionCommit, 'Guix channel introduction commit');
	for (const [name, action] of Object.entries(pins.githubActions)) {
		assertCommit(action.commit, `${name} action commit`);
		assertSha256(action.sourceSha256, `${name} source hash`);
	}
	for (const [name, source] of Object.entries(pins.releaseSources)) {
		if (source.commit) assertCommit(source.commit, `${name} commit`);
		if (source.sha256) assertSha256(source.sha256, `${name} source hash`);
		if (source.recursiveGitBase32) assertBase32(source.recursiveGitBase32, `${name} recursive Git hash`);
	}
	assert(pins.releaseSources.linux.version === '6.18.35-gnu', 'Linux release pin must be 6.18.35.');
	assert(pins.releaseSources.linux.guixPackage === 'stogas-linux-6.18', 'Linux release package must be Stogas custom 6.18.');
	assert(
		pins.releaseSources.edk2.target === 'OvmfPkg/AmdSev/AmdSevX64.dsc',
		'edk2 target must be AmdSevX64.'
	);
}

function verifyChannelsFile() {
	const channels = readFileSync(resolve(releaseRoot, 'guix/channels.scm'), 'utf8');
	assert(channels.includes(`(url "${pins.guix.channel.url}")`), 'channels.scm URL is stale.');
	assert(channels.includes(`(branch "${pins.guix.channel.branch}")`), 'channels.scm branch is stale.');
	assert(channels.includes(`(commit "${pins.guix.channel.commit}")`), 'channels.scm commit is stale.');
	assert(
		channels.includes(`"${pins.guix.channel.introductionCommit}"`),
		'channels.scm introduction commit is stale.'
	);
	assert(
		channels.includes(pins.guix.channel.introductionOpenpgpFingerprint),
		'channels.scm introduction fingerprint is stale.'
	);
	assert(!channels.includes('0000000000000000000000000000000000000000'), 'Guix channel is not pinned.');
}

function verifyWorkflows() {
	const allowedActions = new Map(
		Object.entries(pins.githubActions).map(([name, action]) => [name, action.commit])
	);
	for (const path of workflowPaths) {
		const source = readFileSync(path, 'utf8');
		for (const [name, commit] of allowedActions) {
			if (source.includes(`${name}@`)) {
				assert(source.includes(`${name}@${commit}`), `${basename(path)} does not pin ${name}.`);
			}
		}
		const uses = [...source.matchAll(/uses:\s*([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)@([^\s#]+)/g)];
		for (const [, name, ref] of uses) {
			assert(/^[a-f0-9]{40}$/.test(ref), `${basename(path)} has unpinned action ${name}@${ref}.`);
			assert(allowedActions.get(name) === ref, `${basename(path)} uses unknown action pin ${name}@${ref}.`);
		}
		assert(!source.includes('apt-get install -y guix'), `${basename(path)} installs unpinned Guix.`);
		assert(!source.includes('guix shell'), `${basename(path)} must not use guix shell for release builds.`);
	}
}

function verifyReleaseSources() {
	const releaseSource = releaseSchemePaths.map((path) => readFileSync(path, 'utf8')).join('\n');
	assert(releaseSource.includes('linux-libre@6.18.35'), 'Release graph must inherit linux-libre@6.18.35.');
	assert(releaseSource.includes('stogas-linux-6.18'), 'Release graph must use the Stogas kernel derivation.');
	assert(releaseSource.includes('OvmfPkg/AmdSev/AmdSevX64.dsc'), 'Release graph must build AmdSevX64 OVMF.');
	assert(releaseSource.includes(pins.releaseSources.edk2.recursiveGitBase32), 'edk2 recursive source hash is stale.');
	assert(!releaseSource.includes('linux-libre-6.12'), 'Release graph still references linux-libre-6.12.');
	assert(!releaseSource.includes('ovmf-x86-64') || releaseSource.includes('(inherit ovmf-x86-64)'), 'Release graph must not use generic OVMF output.');
	assert(!releaseSource.includes('go env -w'), 'Release graph must not mutate global Go environment.');
	assert(!releaseSource.includes('--fallback'), 'Release graph must not allow Guix fallback builds.');

	const buildScript = readFileSync(resolve(releaseRoot, 'scripts/build-release.sh'), 'utf8');
	const hydrateScript = readFileSync(resolve(releaseRoot, 'scripts/hydrate-guix-closure.sh'), 'utf8');
	assert(buildScript.includes('--no-substitutes'), 'Final release build must disable substitutes.');
	assert(buildScript.includes("--substitute-urls=''"), 'Final release build must empty substitute URLs.');
	assert(buildScript.includes('--no-offload'), 'Final release build must disable offload.');
	assert(hydrateScript.includes('--dry-run'), 'Hydration must preflight the no-substitutes build.');
	assert(hydrateScript.includes('stogas-(gateway-igvm-release|linux-6\\.18'), 'Hydration allow-list must include only Stogas builds.');

	for (const path of [
		resolve(releaseRoot, 'vendor/virt-firmware-rs/Cargo.lock'),
		resolve(releaseRoot, 'vendor/virt-firmware-rs/.cargo/config.toml'),
		resolve(releaseRoot, 'vendor/igvmmeasure/Cargo.lock'),
		resolve(releaseRoot, 'vendor/igvmmeasure/.cargo/config.toml')
	]) {
		readFileSync(path);
	}
}

async function verifyNetworkHashes() {
	for (const [name, source] of [
		['guix-bootstrap', pins.guix.bootstrapBinary],
		...Object.entries(pins.releaseSources)
	]) {
		if (!source.url || !source.sha256) continue;
		const bytes = await fetchBytes(source.url, name);
		const actual = createHash('sha256').update(bytes).digest('hex');
		assert(actual === source.sha256, `${name} source hash mismatch.`);
	}
}

async function fetchBytes(url, name) {
	const response = await fetch(url, {
		headers: {
			accept: '*/*',
			'user-agent': 'curl/8.0'
		},
		redirect: 'follow'
	});
	if (response.ok) return Buffer.from(await response.arrayBuffer());
	try {
		return execFileSync('curl', ['-fsSL', url], { maxBuffer: 512 * 1024 * 1024 });
	} catch {
		throw new Error(`Could not fetch ${name}: ${response.status} ${response.statusText}`);
	}
}

verifyLockShape();
verifyChannelsFile();
verifyWorkflows();
verifyReleaseSources();
if (process.argv.includes('--network')) await verifyNetworkHashes();
console.log('Release pins verified.');
