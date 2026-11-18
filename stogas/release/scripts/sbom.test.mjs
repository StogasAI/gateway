import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { bom } from './sbom.mjs';

const release = { tag: 'v1.2.3', commit: 'c'.repeat(40), time: '1790000000' };

// The real pins, Guix channel and lockfiles, with a small vendored module list.
function fixture(t) {
	const root = mkdtempSync(join(tmpdir(), 'sbom-'));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	for (const path of ['pins.lock.json', 'guix/channels.scm', 'locks']) {
		cpSync(
			fileURLToPath(new URL(`../${path}`, import.meta.url)),
			join(root, 'stogas/release', path),
			{ recursive: true }
		);
	}
	mkdirSync(join(root, 'transports/vendor'), { recursive: true });
	writeFileSync(
		join(root, 'transports/go.sum'),
		'github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=\n'
	);
	writeFileSync(
		join(root, 'transports/vendor/modules.txt'),
		[
			'# github.com/google/uuid v1.6.0',
			'## explicit',
			'github.com/google/uuid',
			'# example.com/core v1.0.0 => ../core',
			'## explicit; go 1.27',
			'example.com/core',
			'# example.com/upstream v1.0.0 => example.com/fork v1.0.1+incompatible',
			'example.com/upstream',
			'# example.com/verifier v0.1.0 => ../../verifier/go',
			'example.com/verifier',
			'# example.com/unbuilt v1.0.0',
			'## explicit',
			'# example.com/unused => ../unused',
			''
		].join('\n')
	);
	return root;
}

test('the bill of materials lists the pinned sources, crates and built Go modules', (t) => {
	const root = fixture(t);
	const result = bom(root, release);
	const scopes = Object.fromEntries(result.components.map(({ purl, scope }) => [purl, scope]));
	const pins = JSON.parse(readFileSync(join(root, 'stogas/release/pins.lock.json'))).releaseSources;

	assert.equal(scopes[`pkg:github/tianocore/edk2@${pins.edk2.commit}`], 'required');
	assert.equal(scopes[`pkg:golang/stdlib@${pins.go.version}`], 'required');
	assert.equal(scopes[`pkg:github/coconut-svsm/svsm@${pins.svsm.commit}`], 'excluded');
	assert.equal(
		result.components.find(({ name }) => name === 'linux').cpe,
		`cpe:2.3:o:linux:linux_kernel:${pins.linux.version}:*:*:*:*:*:*:*`
	);
	// igvmmeasure alone uses igvm. The NTP daemon in the image also uses digest.
	assert.equal(scopes['pkg:cargo/igvm@0.4.0'], 'excluded');
	assert.equal(scopes['pkg:cargo/digest@0.10.7'], 'required');

	assert.deepEqual(
		result.components
			.filter(({ purl }) => /^pkg:golang\/(?!stdlib)/.test(purl))
			.map(({ purl }) => purl),
		[
			'pkg:golang/example.com/fork@v1.0.1%2Bincompatible',
			'pkg:golang/example.com/verifier@v0.1.0',
			'pkg:golang/github.com/google/uuid@v1.6.0'
		]
	);
	assert.deepEqual(result.components.find(({ name }) => name === 'github.com/google/uuid').hashes, [
		{ alg: 'SHA-256', content: '348bda24330eb231c0f27d630212d2833ac0cf2d4782bfa136b6f9edefbde05d' }
	]);
	assert.equal(result.metadata.component.purl, `pkg:github/StogasAI/gateway@${release.commit}`);
	// Python's uuid.uuid5(uuid.NAMESPACE_URL, 'pkg:github/StogasAI/gateway@v1.2.3').
	assert.equal(result.serialNumber, 'urn:uuid:0d3a489d-abdf-580e-a014-111455599fb7');
	assert.deepEqual(result.dependencies[0].dependsOn, Object.keys(scopes));
});

test('a pinned source without a name in the bill of materials stops the build', (t) => {
	const root = fixture(t);
	const path = join(root, 'stogas/release/pins.lock.json');
	const pins = JSON.parse(readFileSync(path));
	pins.releaseSources.added = { commit: 'a'.repeat(40) };
	writeFileSync(path, JSON.stringify(pins));
	assert.throws(() => bom(root, release), /pinned sources/);
});
