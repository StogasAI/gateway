#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
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
		if (source.guixBase32) assertBase32(source.guixBase32, `${name} Guix base32 source hash`);
		if (source.recursiveGitBase32) assertBase32(source.recursiveGitBase32, `${name} recursive Git hash`);
		if (source.cargoVendorSha256) assertSha256(source.cargoVendorSha256, `${name} Cargo vendor hash`);
		if (source.cargoLockSha256) assertSha256(source.cargoLockSha256, `${name} Cargo.lock hash`);
		if (source.patches) {
			for (const patch of source.patches) {
				assert(typeof patch.file === 'string' && patch.file.endsWith('.patch'), `${name} patch file is invalid.`);
				assertSha256(patch.sha256, `${name} patch hash`);
			}
		}
	}
	assert(pins.releaseSources.linux.version === '6.18.35-gnu', 'Linux release pin must be 6.18.35.');
	assert(pins.releaseSources.linux.guixPackage === 'stogas-linux-6.18', 'Linux release package must be Stogas custom 6.18.');
	assert(
		!pins.releaseSources.linux.requiredBuiltIns.includes('STRICT_MODULE_RWX'),
		'Module RWX hardening must not be claimed while CONFIG_MODULES is disabled.'
	);
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
			if (basename(path) === 'gateway-igvm-release.yml') {
				assert(!source.includes('guix shell'), `${basename(path)} must not use guix shell for release builds.`);
			}
			assert(!source.includes('/gnu/store'), `${basename(path)} must not cache or mutate /gnu/store.`);
			if (source.includes('STOGAS_RELEASE_CI_SKIP_REBUILD_CHECK')) {
				assert(
					basename(path) === 'gateway-igvm-release.yml',
					`${basename(path)} must not skip guix build --check.`
				);
				assert(
					source.includes('STOGAS_RELEASE_CI_SKIP_REBUILD_CHECK: "1"'),
					`${basename(path)} must make the CI rebuild-check skip explicit.`
				);
			}
		if (source.includes('actions/cache@')) {
			assert(source.includes('path: stogas/release/vendor'), `${basename(path)} must cache the Stogas release vendor cache.`);
			if (basename(path) === 'gateway-igvm-release.yml') {
				assert(
					source.includes('path: ~/.cache/guix/checkouts'),
					`${basename(path)} must cache only the Guix channel checkout cache.`
				);
			} else {
				assert(
					!source.includes('path: ~/.cache/guix/checkouts'),
					`${basename(path)} must not cache the Guix channel checkout cache.`
				);
			}
			assert(!source.includes('path: /gnu/store'), `${basename(path)} must not cache the Guix store.`);
			assert(!source.includes('path: ~/.cache/guix/authentication'), `${basename(path)} must not cache Guix authentication state.`);
		}
	}
		const releaseWorkflow = readFileSync(resolve(repoRoot, '.github/workflows/gateway-igvm-release.yml'), 'utf8');
		assert(releaseWorkflow.includes('push:'), 'Release workflow must run from protected tag pushes.');
		assert(releaseWorkflow.includes('tags:'), 'Release workflow must filter pushed tags.');
		assert(releaseWorkflow.includes('"v*.*.*"'), 'Release workflow must match semver-like release tags.');
		assert(!releaseWorkflow.includes('workflow_dispatch:'), 'Release workflow must not accept manual tag input.');
		assert(!releaseWorkflow.includes('inputs.tag'), 'Release workflow must not use a manual tag input.');
		assert(releaseWorkflow.includes('$GITHUB_REF_NAME'), 'Release workflow must use the pushed tag ref name.');
		assert(releaseWorkflow.includes('release_commit="$(git rev-parse HEAD)"'), 'Release publishing must target the checked-out commit.');
		assert(releaseWorkflow.includes('git rev-list -n1 "$tag"'), 'Release workflow must verify the tag points at HEAD.');
		assert(!releaseWorkflow.includes('github.sha'), 'Release workflow must not target github.sha.');
		assert(releaseWorkflow.includes('name: Build IGVM Release'), 'Release workflow must have a separate build job.');
		assert(releaseWorkflow.includes('name: Publish Draft Release'), 'Release workflow must have a separate publish job.');
		assert(releaseWorkflow.includes('contents: write'), 'Publish job must have contents: write.');
		assert(releaseWorkflow.includes('id-token: write'), 'Build job must retain OIDC only for attestation.');
		assert(releaseWorkflow.includes('actions/upload-artifact@'), 'Build job must hand off release assets as a workflow artifact.');
		assert(releaseWorkflow.includes('actions/download-artifact@'), 'Publish job must download build assets before release upload.');
		assert(releaseWorkflow.includes('actions/attest@'), 'Release workflow must use official GitHub artifact attestation.');
		assert(releaseWorkflow.includes('gateway-launch-policy.json'), 'Release workflow must attest and publish gateway-launch-policy.json.');
		assert(
			releaseWorkflow.includes('dist/gateway/${{ github.ref_name }}/gateway.igvm') &&
				releaseWorkflow.includes('dist/gateway/${{ github.ref_name }}/gateway-launch-policy.json'),
			'Release workflow must include both IGVM and launch policy subjects in the official GitHub attestation.'
		);
		assert(!releaseWorkflow.includes('officialGithubArtifactAttestation: false'), 'Release workflow must not emit non-official draft provenance.');
		assert(!releaseWorkflow.includes('github.event.repository.private'), 'Release workflow must not branch on private-repository provenance.');
		assert(!releaseWorkflow.includes('restore-keys:'), 'Release workflow must not restore partial cache matches.');
		assert(releaseWorkflow.includes("'transports/go.mod'"), 'Release cache key must include transports/go.mod.');
		assert(releaseWorkflow.includes("'transports/go.sum'"), 'Release cache key must include transports/go.sum.');
		assert(releaseWorkflow.includes("'core/go.mod'"), 'Release cache key must include core/go.mod.');
		assert(releaseWorkflow.includes("'core/go.sum'"), 'Release cache key must include core/go.sum.');
		assert(
			releaseWorkflow.includes('cd "dist/gateway/$GITHUB_REF_NAME"') &&
				releaseWorkflow.includes('sha256sum -c SHA256SUMS'),
			'Release workflow must verify SHA256SUMS after build and artifact download.'
		);
		assert(releaseWorkflow.includes('Verify release payload file set'), 'Release workflow must verify the final payload file set.');
		assert(releaseWorkflow.includes('release payload contains unexpected files'), 'Release workflow must fail on payload clutter files.');
		assert(releaseWorkflow.includes('gateway-evidence.tar.zst'), 'Release workflow must compress advanced evidence into one archive.');
		assert(releaseWorkflow.includes('gh release delete-asset'), 'Release workflow must delete stale draft release assets before upload.');
		assert(!releaseWorkflow.includes('fetch-sigstore-trust-bundle.mjs'), 'Release workflow must not attach separate Sigstore trust evidence.');
		assert(!releaseWorkflow.includes('sigstore-trust-bundle.json'), 'Release workflow must not upload separate Sigstore trust evidence.');
		assert(releaseWorkflow.includes('gateway.init'), 'Release workflow must archive the init binary evidence.');
		assert(releaseWorkflow.includes('gateway.kernel'), 'Release workflow must archive the kernel image evidence.');
		assert(releaseWorkflow.includes('gateway.initramfs.cpio.zst'), 'Release workflow must archive initramfs evidence.');
		assert(!releaseWorkflow.includes('gateway.ca-certificates.crt'), 'Release workflow must not clutter draft releases with a standalone CA bundle asset.');
		assert(releaseWorkflow.includes('igvmmeasure-check-kvm.txt'), 'Release workflow must upload KVM measurement evidence.');
		assert(!releaseWorkflow.includes('igvm-inspect.txt'), 'Release workflow must not publish measurement output as IGVM inspection evidence.');
		assert(releaseWorkflow.includes('ukify-inspect.txt'), 'Release workflow must upload UKI inspection evidence.');
		assert(releaseWorkflow.includes('guix-describe.txt'), 'Release workflow must upload Guix channel evidence.');
		assert(releaseWorkflow.includes('guix-store-requisites.txt'), 'Release workflow must upload Guix closure evidence.');
		assert(releaseWorkflow.includes('kernel-config.txt'), 'Release workflow must upload kernel config evidence.');
		assert(releaseWorkflow.includes('build-inputs.sha256'), 'Release workflow must upload build-input hash evidence.');

	const prWorkflow = readFileSync(resolve(repoRoot, '.github/workflows/pr-dependencies.yml'), 'utf8');
		assert(prWorkflow.includes('govulncheck'), 'PR dependency workflow must run govulncheck outside the release derivation.');
		assert(prWorkflow.includes("'transports/go.mod'"), 'PR release vendor cache key must include transports/go.mod.');
		assert(prWorkflow.includes("'transports/go.sum'"), 'PR release vendor cache key must include transports/go.sum.');
		assert(prWorkflow.includes("'core/go.mod'"), 'PR release vendor cache key must include core/go.mod.');
		assert(prWorkflow.includes("'core/go.sum'"), 'PR release vendor cache key must include core/go.sum.');
	}

function verifyReleaseSources() {
	const releaseSource = releaseSchemePaths.map((path) => readFileSync(path, 'utf8')).join('\n');
	assert(releaseSource.includes('linux-libre@6.18.35'), 'Release graph must inherit linux-libre@6.18.35.');
	assert(releaseSource.includes('stogas-linux-6.18'), 'Release graph must use the Stogas kernel derivation.');
	assert(releaseSource.includes('OvmfPkg/AmdSev/AmdSevX64.dsc'), 'Release graph must build AmdSevX64 OVMF.');
	assert(releaseSource.includes(pins.releaseSources.edk2.recursiveGitBase32), 'edk2 recursive source hash is stale.');
	assert(releaseSource.includes(pins.releaseSources.virtFirmwareRs.guixBase32), 'virt-firmware-rs source hash is stale.');
	assert(releaseSource.includes(pins.releaseSources.virtFirmwareRs.cargoVendorSha256), 'virt-firmware-rs vendor hash is stale.');
	assert(releaseSource.includes(pins.releaseSources.svsmIgvmMeasure.guixBase32), 'SVSM source hash is stale.');
	assert(releaseSource.includes(pins.releaseSources.svsmIgvmMeasure.cargoVendorSha256), 'SVSM igvmmeasure vendor hash is stale.');
	assert(releaseSource.includes('/stogas/release/vendor/'), 'Gateway source selector must exclude Rust vendor cache.');
	assert(releaseSource.includes('/transports/vendor/'), 'Gateway source selector must exclude Go vendor cache.');
	assert(releaseSource.includes('(define (runtime-source-path? file)'), 'Gateway source selector must be allowlisted.');
	assert(releaseSource.includes('(define (gateway-relative-path file)'), 'Gateway source selector must normalize absolute local-file paths.');
	assert(releaseSource.includes('(string-prefix? "core/" file)'), 'Gateway source selector must include core only by allowlist.');
	assert(releaseSource.includes('(string-prefix? "transports/" file)'), 'Gateway source selector must include transports only by allowlist.');
		assert(releaseSource.includes('vendor/go-modcache'), 'Release graph must consume the hydrated Go module cache.');
		assert(releaseSource.includes('build-inputs.sha256'), 'Release graph must emit build input hashes.');
		assert(releaseSource.includes('gateway.init'), 'Release graph must emit the Go init binary.');
		assert(releaseSource.includes('gateway-launch-policy.json'), 'Release graph must emit the launch policy artifact.');
		assert(releaseSource.includes('stogas.gateway.launch-policy.v1'), 'Release graph must stamp the launch policy schema.');
		assert(releaseSource.includes('\\"policy\\": \\"0x0000000000030000\\"'), 'Launch policy must record the expected SNP policy.');
		assert(releaseSource.includes('\\"vmpl\\": 0'), 'Launch policy must record VMPL 0.');
		assert(releaseSource.includes('gateway.kernel'), 'Release graph must emit the kernel image.');
		assert(releaseSource.includes('gateway.initramfs.cpio.zst'), 'Release graph must emit the compressed initramfs.');
		assert(!releaseSource.includes('gateway.ca-certificates.crt'), 'Release graph must not emit a standalone CA bundle artifact.');
		assert(releaseSource.includes('(pkg "nss-certs")'), 'Release graph must consume Guix nss-certs.');
		assert(releaseSource.includes('/etc/ssl/certs/ca-certificates.crt'), 'Release graph must install the guest CA bundle at the standard path.');
		assert(releaseSource.includes('guestCaBundleSha256'), 'Release manifest must record the guest CA bundle hash.');
		assert(releaseSource.includes('guix/nss-certs/ca-certificates.crt'), 'Build input hashes must include the Guix CA bundle.');
		assert(releaseSource.includes('coreGoModSha256'), 'Release manifest must record core/go.mod hash.');
		assert(releaseSource.includes('coreGoSumSha256'), 'Release manifest must record core/go.sum hash.');
		assert(releaseSource.includes('(cons "core/go.mod"'), 'Build input hashes must include core/go.mod.');
		assert(releaseSource.includes('(cons "core/go.sum"'), 'Build input hashes must include core/go.sum.');
		assert(releaseSource.includes('igvmmeasure-check-kvm.txt'), 'Release graph must emit KVM measurement output.');
		assert(!releaseSource.includes('igvm-inspect.txt'), 'Release graph must not publish measurement output as IGVM inspection output.');
		assert(releaseSource.includes('ukify-inspect.txt'), 'Release graph must emit UKI inspection output.');
		assert(releaseSource.includes('kernel-config.txt'), 'Release graph must emit the kernel config.');
		assert(releaseSource.includes('\\"platform\\": \\"SEV_SNP\\"'), 'Release manifest must record measured SNP platform.');
		assert(releaseSource.includes('\\"vmm\\": \\"qemu-kvm\\"'), 'Release manifest must record measured VMM path.');
		assert(releaseSource.includes('\\"measurementTool\\": \\"igvmmeasure\\"'), 'Release manifest must record measurement tool.');
		assert(releaseSource.includes('measurementToolVersion'), 'Release manifest must record measurement tool version.');
		assert(releaseSource.includes('measurementToolSha256'), 'Release manifest must record measurement tool hash.');
		assert(releaseSource.includes('igvmmeasure --check-kvm gateway.igvm measure'), 'Release manifest must record measurement command.');
		assert(releaseSource.includes('\\"checkKvm\\": true'), 'Release manifest must record KVM measurement mode.');
		assert(!releaseSource.includes('linux-libre-6.12'), 'Release graph still references linux-libre-6.12.');
		assert(!releaseSource.includes('ovmf-x86-64') || releaseSource.includes('(inherit ovmf-x86-64)'), 'Release graph must not use generic OVMF output.');
	assert(!releaseSource.includes('go env -w'), 'Release graph must not mutate global Go environment.');
	assert(!releaseSource.includes('--fallback'), 'Release graph must not allow Guix fallback builds.');
	assert(releaseSource.includes('(setenv "GOPROXY" "off")'), 'Release graph must disable GOPROXY.');
	assert(releaseSource.includes('(setenv "GOSUMDB" "off")'), 'Release graph must disable GOSUMDB.');
	assert(releaseSource.includes('(setenv "GOTOOLCHAIN" "local")'), 'Release graph must use local Go toolchain only.');
	assert(releaseSource.includes('(setenv "GOWORK" "off")'), 'Release graph must disable Go workspaces.');
	assert(releaseSource.includes('(setenv "CGO_ENABLED" "0")'), 'Release graph must disable CGO.');
		assert(releaseSource.includes('(invoke "go" "mod" "verify")'), 'Release graph must verify hydrated Go modules offline.');
		assert(releaseSource.includes('(invoke "go" "mod" "vendor")'), 'Release graph must regenerate Go vendor inside the sandbox.');
		assert(releaseSource.includes('(invoke "sha256sum" "-c" "/tmp/go-before.sha256")'), 'Release graph must fail if offline vendoring mutates go.mod or go.sum.');
		assert(releaseSource.includes('go-vendor.sha256'), 'Release graph must consume the hydrated Go vendor tree hash.');
		assert(releaseSource.includes('Go vendor tree hash mismatch'), 'Release graph must fail if regenerated Go vendor tree differs.');
		assert(releaseSource.includes('goVendorTreeSha256'), 'Release manifest must record the Go vendor tree hash.');
		assert(releaseSource.includes('"-mod=vendor"'), 'Release graph must compile from Go vendor only.');
		assert(releaseSource.includes('(setenv "LC_ALL" "C")'), 'Release graph must pin LC_ALL.');
		assert(releaseSource.includes('(setenv "TZ" "UTC")'), 'Release graph must pin TZ.');
		assert(releaseSource.includes('(umask #o022)'), 'Release graph must pin umask.');
		assert(releaseSource.includes('zstd -19 -T1 --no-progress'), 'Release graph must use single-threaded zstd.');
		assert(releaseSource.includes('"CONFIG_STACKPROTECTOR"') || releaseSource.includes('"STACKPROTECTOR"'), 'Kernel config must explicitly enable stack protector.');
		assert(releaseSource.includes('"STACKPROTECTOR_STRONG"'), 'Kernel config must explicitly enable strong stack protector.');
		assert(releaseSource.includes('"FORTIFY_SOURCE"'), 'Kernel config must explicitly enable fortify source.');
		assert(releaseSource.includes('"HARDENED_USERCOPY"'), 'Kernel config must explicitly enable hardened usercopy.');
		assert(releaseSource.includes('"STRICT_KERNEL_RWX"'), 'Kernel config must explicitly enable strict kernel RWX.');
		assert(releaseSource.includes('"RANDOMIZE_BASE"'), 'Kernel config must explicitly enable KASLR.');
		assert(releaseSource.includes('"SECCOMP_FILTER"'), 'Kernel config must explicitly enable seccomp filters.');
		assert(releaseSource.includes('"PACKET"'), 'Kernel config must explicitly disable raw packet sockets.');
		assert(releaseSource.includes('"VIRTIO_PCI_LEGACY"'), 'Kernel config must explicitly disable legacy virtio PCI.');

		const buildScript = readFileSync(resolve(releaseRoot, 'scripts/build-release.sh'), 'utf8');
	const hydrateScript = readFileSync(resolve(releaseRoot, 'scripts/hydrate-guix-closure.sh'), 'utf8');
	const goHydrateScript = readFileSync(resolve(releaseRoot, 'scripts/hydrate-go-vendor.sh'), 'utf8');
	const rustHydrateScript = readFileSync(resolve(releaseRoot, 'scripts/hydrate-rust-vendor.sh'), 'utf8');
		assert(buildScript.includes('--no-substitutes'), 'Final release build must disable substitutes.');
		assert(buildScript.includes("--substitute-urls=''"), 'Final release build must empty substitute URLs.');
		assert(buildScript.includes('--no-offload'), 'Final release build must disable offload.');
		assert(!buildScript.includes('--no-grafts'), 'Final release build must keep Guix grafts enabled.');
		assert(buildScript.includes('guix-describe.txt'), 'Build script must add Guix describe evidence.');
		assert(buildScript.includes('guix-store-requisites.txt'), 'Build script must add Guix store requisite evidence.');
		assert(buildScript.includes('expected_files=('), 'Build script must keep a tight release output allow-list.');
		assert(buildScript.includes('release output contains unexpected files'), 'Build script must fail on clutter files.');
		assert(buildScript.includes('sha256sum -c SHA256SUMS'), 'Build script must verify generated release checksums.');
		assert(buildScript.includes('STOGAS_RELEASE_CI_SKIP_REBUILD_CHECK'), 'Build script must gate CI no-check builds explicitly.');
		assert(hydrateScript.includes('--dry-run'), 'Hydration must preflight the no-substitutes build.');
		assert(!hydrateScript.includes('2>&1 || true'), 'Hydration dry run must fail closed on unexpected Guix errors.');
		assert(hydrateScript.includes('cat "$dry_run" >&2'), 'Hydration dry-run failure must print Guix output.');
		assert(!hydrateScript.includes('--no-grafts'), 'Hydration must keep Guix grafts enabled.');
	assert(hydrateScript.includes('stogas-(gateway-igvm-release|linux-6\\.18'), 'Hydration allow-list must include only Stogas builds.');
	assert(hydrateScript.includes('hydrate-go-vendor.sh'), 'Closure hydration must refresh Go vendor cache first.');
	assert(hydrateScript.includes('hydrate-rust-vendor.sh'), 'Closure hydration must refresh Rust vendor cache first.');
	assert(goHydrateScript.includes('go mod tidy'), 'Go hydration must tidy the module graph.');
	assert(goHydrateScript.includes('go mod download'), 'Go hydration must download modules before verification.');
	assert(goHydrateScript.includes('go mod verify'), 'Go hydration must verify downloaded modules.');
		assert(goHydrateScript.includes('go mod vendor'), 'Go hydration must regenerate vendor from verified modules.');
		assert(goHydrateScript.includes('go mod vendor -o "$STOGAS_GO_VENDOR"'), 'Go hydration must place the release-owned vendor cache under stogas/release/vendor.');
		assert(goHydrateScript.includes('vendorTreeSha256'), 'Go hydration must hash the regenerated vendor source tree.');
		assert(goHydrateScript.includes('go-vendor.sha256'), 'Go hydration must write the vendor tree hash for the final derivation.');
		assert(goHydrateScript.includes('Restored Go release cache failed verification'), 'Go hydration must purge and retry untrusted restored caches.');
		assert(goHydrateScript.includes('go_mod_before='), 'Go hydration must snapshot go.mod before hydration.');
	assert(goHydrateScript.includes('go_sum_before='), 'Go hydration must snapshot go.sum before hydration.');
	assert(goHydrateScript.includes('Go hydration changed transports/go.mod or transports/go.sum'), 'Go hydration must fail if tidy changes the ledger.');
	assert(goHydrateScript.includes('sum.golang.org'), 'Go hydration must use the public Go checksum database.');
	assert(goHydrateScript.includes('GOFLAGS=-modcacherw'), 'Go hydration must keep the ignored module cache removable.');
	assert(goHydrateScript.includes('guix time-machine'), 'Go hydration must use Go from the pinned Guix channel.');
	assert(goHydrateScript.includes('go@1.26'), 'Go hydration must use the pinned Guix Go package.');
	assert(!goHydrateScript.includes('command -v go'), 'Go hydration must not depend on ambient native Go.');
	assert(rustHydrateScript.includes('cargo vendor --locked'), 'Rust hydration must use locked Cargo vendoring.');
	assert(rustHydrateScript.includes('guix time-machine'), 'Rust hydration must use Cargo from the pinned Guix channel.');
	assert(!rustHydrateScript.includes('command -v cargo'), 'Rust hydration must not depend on ambient native Cargo.');
	assert(rustHydrateScript.includes('sha256sum'), 'Rust hydration must verify source and cache hashes.');

	for (const path of [
		resolve(releaseRoot, 'locks/virt-firmware-rs.Cargo.lock'),
		resolve(releaseRoot, 'locks/igvmmeasure.Cargo.lock'),
		resolve(releaseRoot, 'patches/virt-firmware-rs-kvm-vmsa-last.patch'),
		resolve(releaseRoot, 'patches/svsm-igvmmeasure-standalone-cargo.patch')
	]) {
		readFileSync(path);
	}

	verifyFileHash(
		resolve(releaseRoot, 'locks/virt-firmware-rs.Cargo.lock'),
		pins.releaseSources.virtFirmwareRs.cargoLockSha256,
		'virt-firmware-rs Cargo.lock'
	);
	verifyFileHash(
		resolve(releaseRoot, 'locks/igvmmeasure.Cargo.lock'),
		pins.releaseSources.svsmIgvmMeasure.cargoLockSha256,
		'igvmmeasure Cargo.lock'
	);
	for (const [sourceName, source] of Object.entries(pins.releaseSources)) {
		for (const patch of source.patches ?? []) {
			verifyFileHash(resolve(releaseRoot, 'patches', patch.file), patch.sha256, `${sourceName} patch ${patch.file}`);
			assert(releaseSource.includes(patch.file), `Release graph does not apply ${patch.file}.`);
		}
	}
	const trackedVendor = execFileSync('git', ['-C', repoRoot, 'ls-files', '--cached', '--', 'stogas/release/vendor/**'], {
		encoding: 'utf8'
	})
		.split('\n')
		.filter(Boolean)
		.filter((file) => existsSync(resolve(repoRoot, file)))
		.join('\n');
	assert(trackedVendor === '', 'stogas/release/vendor must remain an untracked local cache.');
	const trackedGoVendor = execFileSync('git', ['-C', repoRoot, 'ls-files', '--cached', '--', 'transports/vendor/**'], {
		encoding: 'utf8'
	})
		.split('\n')
		.filter(Boolean)
		.filter((file) => existsSync(resolve(repoRoot, file)))
		.join('\n');
	assert(trackedGoVendor === '', 'transports/vendor must remain an untracked local cache.');
}

function verifyGoAudit() {
	const audit = readFileSync(resolve(releaseRoot, 'BUILD_AUDIT.md'), 'utf8');
	readFileSync(resolve(repoRoot, 'transports/go.mod'));
	readFileSync(resolve(repoRoot, 'transports/go.sum'));
	assert(!audit.includes('apps/api/'), 'BUILD_AUDIT.md paths must be relative to the gateway repository root.');
	assert(!audit.includes('| Module | Version |'), 'BUILD_AUDIT.md must not duplicate the Go module hash ledger.');
	assert(!/sigstore|provenance|attestation/i.test(audit), 'BUILD_AUDIT.md must stay scoped to reproducible build inputs.');
	assert(audit.includes('Pure-Source Go Hydration'), 'BUILD_AUDIT.md must document the Go hydration boundary.');
	assert(audit.includes('sum.golang.org'), 'BUILD_AUDIT.md must document Go checksum database verification.');
	assert(audit.includes('GOFLAGS=-modcacherw'), 'BUILD_AUDIT.md must document removable Go cache behavior.');
	assert(audit.includes('go.sum'), 'BUILD_AUDIT.md must name go.sum as the Go dependency ledger.');
	assert(audit.includes('GOPROXY=off'), 'BUILD_AUDIT.md must document offline Go release mode.');
	assert(audit.includes('stogas/release/vendor/go-vendor'), 'BUILD_AUDIT.md must document the release-owned Go vendor cache.');
	assert(audit.includes('transports/vendor/'), 'BUILD_AUDIT.md must document the untracked Go vendor cache.');
	assert(audit.includes('--check'), 'BUILD_AUDIT.md must document release guix build --check.');
}

function verifyFileHash(path, expected, label) {
	const actual = createHash('sha256').update(readFileSync(path)).digest('hex');
	assert(actual === expected, `${label} hash mismatch.`);
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
verifyGoAudit();
if (process.argv.includes('--network')) await verifyNetworkHashes();
console.log('Release pins verified.');
