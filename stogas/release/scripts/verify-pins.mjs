#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readdirSync,
	rmSync,
	symlinkSync,
	writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const releaseRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(releaseRoot, '../..');
const pins = JSON.parse(readFileSync(resolve(releaseRoot, 'pins.lock.json'), 'utf8'));

if (process.argv.length !== 2) throw new Error('verify-pins.mjs does not accept arguments.');

function assert(condition, message) {
	if (!condition) throw new Error(message);
}

function read(path) {
	return readFileSync(path, 'utf8');
}

function assertContains(source, value, message) {
	assert(source.includes(value), message);
}

function assertSha256(value, label) {
	assert(typeof value === 'string' && /^[a-f0-9]{64}$/.test(value), `${label} is not SHA-256.`);
}

function assertBase32(value, label) {
	assert(typeof value === 'string' && /^[a-z0-9]{52}$/.test(value), `${label} is not Guix base32.`);
}

function assertCommit(value, label) {
	assert(
		typeof value === 'string' && /^[a-f0-9]{40}$/.test(value),
		`${label} is not a full Git commit.`
	);
}

function fileSha256(path) {
	return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function sha256HexToGuixBase32(hex) {
	const alphabet = '0123456789abcdfghijklmnpqrsvwxyz';
	const bytes = Buffer.from(hex, 'hex');
	let encoded = '';
	for (let bit = bytes.length * 8 - 1; bit >= 0; bit -= 5) {
		const byte = Math.floor(bit / 8);
		const shift = bit % 8;
		let quintet = bytes[byte] >> shift;
		if (byte + 1 < bytes.length) quintet |= bytes[byte + 1] << (8 - shift);
		encoded += alphabet[quintet & 0x1f];
	}
	return encoded;
}

function verifyLock() {
	assert(pins.schema === 'stogas.gateway.release.pins.v1', 'Unsupported release pin schema.');
	assertSha256(pins.guix.bootstrapBinary.sha256, 'Guix bootstrap hash');
	assertCommit(pins.guix.channel.commit, 'Guix channel commit');
	assertCommit(pins.guix.channel.introductionCommit, 'Guix introduction commit');
	assert(
		typeof pins.guix.channel.introductionOpenpgpFingerprint === 'string' &&
			pins.guix.channel.introductionOpenpgpFingerprint.length > 0,
		'Guix introduction fingerprint is missing.'
	);

	for (const [name, action] of Object.entries(pins.githubActions)) {
		assert(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(name), `Invalid action name: ${name}`);
		assertCommit(action.commit, `${name} commit`);
		assert(
			JSON.stringify(Object.keys(action).sort()) === JSON.stringify(['commit', 'tag']),
			`${name} has unsupported fields.`
		);
	}

	for (const [name, source] of Object.entries(pins.releaseSources)) {
		if (source.commit) assertCommit(source.commit, `${name} commit`);
		if (source.sha256) assertSha256(source.sha256, `${name} source hash`);
		if (source.guixBase32) {
			assertBase32(source.guixBase32, `${name} Guix source hash`);
			assert(
				sha256HexToGuixBase32(source.sha256) === source.guixBase32,
				`${name} source hashes differ.`
			);
		}
		if (source.recursiveGitBase32) {
			assertBase32(source.recursiveGitBase32, `${name} recursive Git hash`);
		}
		if (source.cargoVendorSha256) {
			assertSha256(source.cargoVendorSha256, `${name} Cargo vendor hash`);
		}
		if (source.cargoLockSha256) {
			assertSha256(source.cargoLockSha256, `${name} Cargo lock hash`);
		}
	}

	const go = pins.releaseSources.go;
	assertBase32(go.guixSourceBase32, 'Go Guix source hash');
	assert(sha256HexToGuixBase32(go.sha256) === go.guixSourceBase32, 'Go source hashes differ.');
	assert(
		pins.releaseSources.edk2.target === 'OvmfPkg/AmdSev/AmdSevX64.dsc',
		'The release must use AmdSevX64 OVMF.'
	);
	for (const name of ['virtFirmwareRs', 'svsmIgvmMeasure']) {
		assert(
			pins.releaseSources[name].patches?.length === 1,
			`${name} must use one self-contained Stogas patch.`
		);
	}
}

function verifyPatches() {
	const expected = [];
	for (const [sourceName, source] of Object.entries(pins.releaseSources)) {
		for (const patch of source.patches ?? []) {
			assert(
				typeof patch.file === 'string' &&
					/^[A-Za-z0-9][A-Za-z0-9._-]*\.patch$/.test(patch.file) &&
					basename(patch.file) === patch.file,
				`${sourceName} has an unsafe patch name.`
			);
			assertSha256(patch.sha256, `${sourceName} patch hash`);
			assert(!expected.includes(patch.file), `Patch is pinned twice: ${patch.file}`);
			expected.push(patch.file);
		}
	}

	const patchRoot = resolve(releaseRoot, 'patches');
	const actual = readdirSync(patchRoot).sort();
	assert(
		JSON.stringify(actual) === JSON.stringify(expected.sort()),
		'The patch directory must exactly match pins.lock.json.'
	);

	const packages = read(resolve(releaseRoot, 'guix/modules/stogas/release/packages.scm'));
	const hydration = read(resolve(releaseRoot, 'scripts/hydrate-rust-vendor.sh'));
	assertContains(hydration, 'apply_pinned_patches', 'Rust hydration must read the patch ledger.');
	for (const patch of actual) {
		const path = resolve(patchRoot, patch);
		assert(fileSha256(path) === patchEntry(patch).sha256, `${patch} hash mismatch.`);
		const source = read(path);
		assert(!/^GIT binary patch$/m.test(source), `${patch} must be a text patch.`);
		const headers = [...source.matchAll(/^(---|\+\+\+)\s+([^\t\n ]+)/gm)];
		assert(headers.length >= 2, `${patch} has no unified diff headers.`);
		for (const [, marker, pathName] of headers) {
			const prefix = marker === '---' ? 'a/' : 'b/';
			assert(pathName.startsWith(prefix), `${patch} has a non-local path.`);
			const relative = pathName.slice(2);
			assert(
				relative.length > 0 && !relative.startsWith('/') && !relative.split('/').includes('..'),
				`${patch} has an unsafe path.`
			);
		}
		assertContains(packages, `(patch-file "${patch}")`, `Guix does not apply ${patch}.`);
		assert(!hydration.includes(` ${patch}`), 'Rust hydration must not duplicate patch filenames.');
	}
}

function patchEntry(file) {
	for (const source of Object.values(pins.releaseSources)) {
		const entry = source.patches?.find((patch) => patch.file === file);
		if (entry) return entry;
	}
	throw new Error(`Unpinned patch: ${file}`);
}

function verifyChannels() {
	const source = read(resolve(releaseRoot, 'guix/channels.scm'));
	const channel = pins.guix.channel;
	for (const value of [
		channel.url,
		channel.branch,
		channel.commit,
		channel.introductionCommit,
		channel.introductionOpenpgpFingerprint
	]) {
		assertContains(source, value, 'guix/channels.scm does not match pins.lock.json.');
	}
}

function verifyWorkflows() {
	const paths = [
		resolve(repoRoot, '.github/workflows/gateway-igvm-release.yml'),
		resolve(repoRoot, '.github/workflows/pr-dependencies.yml')
	];
	const allowed = new Map(
		Object.entries(pins.githubActions).map(([name, action]) => [name, action.commit])
	);
	const used = new Set();
	for (const path of paths) {
		const source = read(path);
		for (const [, name, ref] of source.matchAll(
			/uses:\s*([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)@([^\s#]+)/g
		)) {
			assert(allowed.get(name) === ref, `${basename(path)} has an unpinned action: ${name}@${ref}`);
			used.add(name);
		}
		assert(!source.includes('/gnu/store'), `${basename(path)} must not cache the Guix store.`);
		assert(!source.includes('apt-get install -y guix'), `${basename(path)} uses unpinned Guix.`);
	}
	assert(
		JSON.stringify([...used].sort()) === JSON.stringify([...allowed.keys()].sort()),
		'pins.lock.json contains a missing or unused GitHub Action.'
	);

	const release = read(paths[0]);
	for (const value of [
		'push:',
		'tags:',
		"- 'v*.*.*'",
		'Build IGVM Release',
		'Publish Draft Release',
		'actions/attest@',
		'gateway.igvm',
		'release-manifest.json',
		'snp-launch-policies.json',
		'github-attestation.jsonl',
		'Verify release payload file set',
		'find . -mindepth 1 -maxdepth 1',
		'release payload entry is not a regular file',
		'gh attestation verify',
		'Downloaded release payload does not match its attested manifest.',
		'gh release delete-asset'
	]) {
		assertContains(release, value, `Release workflow is missing: ${value}`);
	}
	assert(!release.includes('workflow_dispatch:'), 'Release builds must start from protected tags.');
	assert(!release.includes('restore-keys:'), 'Release caches must not use partial matches.');
	assert(
		!release.includes('SHA256SUMS'),
		'The manifest makes a separate checksum asset redundant.'
	);
	assertContains(
		release,
		'subject-path: dist/gateway/${{ github.ref_name }}/release-manifest.json',
		'GitHub must attest the manifest that links the full release.'
	);
	assert(
		!release.includes('gateway-evidence.tar'),
		'Release assets must not contain a redundant evidence archive.'
	);
	assert(
		!release.includes('STOGAS_RELEASE_SINGLE_BUILD'),
		'The release workflow must use the one build path.'
	);
	assertContains(
		release,
		'stogas/release/scripts/build-release.sh "$GITHUB_REF_NAME"',
		'The release workflow must use the canonical build script.'
	);
	for (const file of [
		'gateway.init',
		'gateway.kernel',
		'gateway.initramfs.cpio.zst',
		'kernel-config.txt'
	]) {
		assertContains(release, file, `The workflow must remove local-only output: ${file}`);
	}

	const dependencies = read(paths[1]);
	assertContains(dependencies, 'govulncheck', 'The dependency workflow must run govulncheck.');
	assertContains(
		dependencies,
		'path: stogas/release/vendor',
		'The dependency workflow must cache only verified vendor inputs.'
	);
}

function verifyReleaseGraph() {
	const release = read(resolve(releaseRoot, 'guix/release.scm'));
	const packages = read(resolve(releaseRoot, 'guix/modules/stogas/release/packages.scm'));
	const graph = `${release}\n${packages}`;
	const sources = pins.releaseSources;
	for (const value of [
		sources.go.url,
		sources.go.guixSourceBase32,
		`go@${sources.go.guixRecipeBaseVersion}`,
		sources.systemdUkify.url,
		sources.systemdUkify.guixBase32,
		sources.edk2.commit,
		sources.edk2.recursiveGitBase32,
		sources.virtFirmwareRs.url,
		sources.virtFirmwareRs.guixBase32,
		sources.virtFirmwareRs.cargoVendorSha256,
		sources.svsmIgvmMeasure.url,
		sources.svsmIgvmMeasure.guixBase32,
		sources.svsmIgvmMeasure.cargoVendorSha256
	]) {
		assertContains(graph, value, `The Guix graph is missing pinned value: ${value}`);
	}
	assert(
		(graph.match(/\(invoke "cargo" "test"/g) ?? []).length === 2,
		'Both patched Rust tools must test inside Guix.'
	);
	for (const value of [
		'(setenv "GOENV" "off")',
		'(setenv "GOPROXY" "off")',
		'(setenv "GOSUMDB" "off")',
		'(setenv "GOTOOLCHAIN" "local")',
		'(setenv "GOWORK" "off")',
		'(setenv "CGO_ENABLED" "0")',
		'"-mod=vendor"',
		'Go vendor tree hash mismatch',
		'(setenv "LC_ALL" "C")',
		'(setenv "TZ" "UTC")',
		'(umask #o022)',
		'"--cpus" "4"',
		'"--real16"',
		'igvmmeasure" "--check-kvm"',
		'\\"launchPolicies\\":~a',
		'%snp-launch-policies',
		'\\"vcpuCount\\":4',
		'(invoke "scripts/config" "--set-val" "NR_CPUS" "4")',
		'(gateway-file "LICENSE" "LICENSE")',
		'(gateway-file "NOTICE" "NOTICE")'
	]) {
		assertContains(graph, value, `The release graph is missing: ${value}`);
	}
	for (const removed of [
		'build-inputs.sha256',
		'guix-describe.txt',
		'guix-store-requisites.txt',
		'igvmmeasure-check-kvm.txt',
		'launch-measurement.txt',
		'SHA256SUMS',
		'ukify-inspect.txt'
	]) {
		assert(!release.includes(removed), `The release still emits redundant file: ${removed}`);
	}
	assert(!release.includes('out "/gateway.efi"'), 'The release must not emit a separate UKI.');
	assert(!release.includes('out "/pins.lock.json"'), 'The release must not copy its source lock.');

	const cmdline = read(resolve(releaseRoot, 'guix/cmdline.txt'));
	assertContains(cmdline, 'ip=dhcp', 'The guest kernel command line must request DHCP.');

	const build = read(resolve(releaseRoot, 'scripts/build-release.sh'));
	for (const value of [
		'--no-substitutes',
		"--substitute-urls=''",
		'--no-offload',
		'resolve_stogas_guix "$release_root"',
		'export STOGAS_GATEWAY_SOURCE_ROOT="$source_snapshot"',
		'expected_files=(',
		'find . -mindepth 1 -maxdepth 1',
		'release output contains unexpected files',
		'release output entry is not a regular file'
	]) {
		assertContains(build, value, `The build wrapper is missing: ${value}`);
	}
	assert(
		(build.match(/"\$STOGAS_GUIX" build/g) ?? []).length === 1,
		'The build wrapper must run the final Guix build once.'
	);
	assert(
		!build.includes('build_release --check'),
		'The build wrapper must not rebuild in one store.'
	);
	assert(
		!build.includes('STOGAS_RELEASE_SINGLE_BUILD'),
		'The build wrapper must have one build mode.'
	);
	assert(!build.includes('--no-grafts'), 'The build must keep pinned-channel grafts.');

	const hydrate = read(resolve(releaseRoot, 'scripts/hydrate-guix-closure.sh'));
	for (const value of [
		'hydrate-go-vendor.sh',
		'hydrate-rust-vendor.sh',
		'--development',
		'--root="$roots_dir/inputs"',
		'--dry-run',
		'the final build would build non-release derivations'
	]) {
		assertContains(hydrate, value, `Guix hydration is missing: ${value}`);
	}
	assert(!hydrate.includes('--root="$roots_dir/release"'), 'Hydration must not build the release.');
	assert(!hydrate.includes('2>&1 || true'), 'Hydration must fail closed.');

	const goHydrate = read(resolve(releaseRoot, 'scripts/hydrate-go-vendor.sh'));
	for (const value of [
		'go mod tidy',
		'go mod download',
		'go mod verify',
		'go mod vendor -o "$STOGAS_GO_VENDOR"',
		'sum.golang.org',
		'gateway_source_root="${STOGAS_GATEWAY_SOURCE_ROOT:-$repo_root}"',
		'export GOENV=off',
		'Go hydration changed a committed go.mod or go.sum ledger',
		'"$STOGAS_GUIX" shell'
	]) {
		assertContains(goHydrate, value, `Go hydration is missing: ${value}`);
	}

	const rustHydrate = read(resolve(releaseRoot, 'scripts/hydrate-rust-vendor.sh'));
	for (const value of [
		'cargo vendor --locked',
		'CARGO_HOME="$STOGAS_CARGO_HOME"',
		'patch --batch --forward --fuzz=0',
		'apply_pinned_patches',
		'vendor_cache_valid',
		'"$STOGAS_GUIX" shell'
	]) {
		assertContains(rustHydrate, value, `Rust hydration is missing: ${value}`);
	}

	const guix = read(resolve(releaseRoot, 'scripts/guix.sh'));
	assertContains(guix, 'guix time-machine --no-channel-files', 'Guix must use the pinned channel.');
	assertContains(
		guix,
		'unset GUIX_BUILD_OPTIONS GUIX_EXTENSIONS_PATH GUIX_PACKAGE_PATH',
		'Guix must discard ambient build options.'
	);

	const bootstrap = read(resolve(releaseRoot, 'scripts/install-guix-bootstrap.sh'));
	assertContains(bootstrap, "--proto '=https'", 'Guix bootstrap downloads must use HTTPS.');
	assertContains(bootstrap, 'sha256sum --check --strict', 'Guix bootstrap bytes must be verified.');
	assertContains(
		bootstrap,
		'unsafe Guix builder account settings',
		'Guix builders must be validated.'
	);

	for (const [path, expected, label] of [
		[
			resolve(releaseRoot, 'locks/virt-firmware-rs.Cargo.lock'),
			sources.virtFirmwareRs.cargoLockSha256,
			'virt-firmware-rs Cargo.lock'
		],
		[
			resolve(releaseRoot, 'locks/igvmmeasure.Cargo.lock'),
			sources.svsmIgvmMeasure.cargoLockSha256,
			'igvmmeasure Cargo.lock'
		]
	]) {
		assert(fileSha256(path) === expected, `${label} hash mismatch.`);
	}

	for (const path of ['stogas/release/vendor/**', 'transports/vendor/**']) {
		const tracked = execFileSync('git', ['-C', repoRoot, 'ls-files', '--cached', '--', path], {
			encoding: 'utf8'
		})
			.split('\n')
			.filter(Boolean)
			.filter((file) => existsSync(resolve(repoRoot, file)));
		assert(tracked.length === 0, `${path} must remain an untracked cache.`);
	}
}

function verifyTreeHasher() {
	const script = resolve(releaseRoot, 'scripts/tree-sha256.sh');
	const temporaryRoot = mkdtempSync(join(tmpdir(), 'stogas-tree-hash-'));
	const first = join(temporaryRoot, 'first');
	const second = join(temporaryRoot, 'second');
	const hash = (path) =>
		execFileSync(script, [path], {
			encoding: 'utf8',
			stdio: ['ignore', 'pipe', 'pipe']
		}).trim();
	try {
		for (const root of [first, second]) {
			mkdirSync(join(root, 'empty'), { recursive: true, mode: 0o755 });
			writeFileSync(join(root, 'input'), 'pinned input\n', { mode: 0o644 });
		}
		const expected = hash(first);
		assert(hash(second) === expected, 'Equivalent vendor trees must have one hash.');
		chmodSync(join(second, 'input'), 0o755);
		assert(hash(second) !== expected, 'Vendor hashes must include executable mode.');
		chmodSync(join(second, 'input'), 0o644);
		mkdirSync(join(second, 'extra-empty'), { mode: 0o755 });
		assert(hash(second) !== expected, 'Vendor hashes must include empty directories.');
		symlinkSync('input', join(first, 'link'));
		let rejected = false;
		try {
			hash(first);
		} catch {
			rejected = true;
		}
		assert(rejected, 'Vendor hashes must reject symbolic links.');
	} finally {
		rmSync(temporaryRoot, { recursive: true, force: true });
	}
}

verifyLock();
verifyPatches();
verifyChannels();
verifyWorkflows();
verifyReleaseGraph();
verifyTreeHasher();
console.log('Release pins verified.');
