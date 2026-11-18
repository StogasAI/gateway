#!/usr/bin/env node
// Writes the CycloneDX bill of materials of a release from its captured source, so the same tag
// gives the same bytes.
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const IMAGE = 'required';
// CycloneDX names a component that the build uses and the image does not contain "excluded".
const BUILD_TOOL = 'excluded';

// The name that vulnerability databases use for each pinned source. A CPE names the sources that
// only the NVD tracks.
const SOURCES = {
	edk2: {
		purl: 'pkg:github/tianocore/edk2',
		cpe: (version) => `cpe:2.3:a:tianocore:edk2:${version.replace('edk2-stable', '')}`,
		scope: IMAGE
	},
	efiloader: { purl: 'pkg:github/ardbiesheuvel/efiloader', scope: BUILD_TOOL },
	// The image holds the standard library that this toolchain compiles into the gateway.
	go: {
		purl: 'pkg:golang/stdlib',
		cpe: (version) => `cpe:2.3:a:golang:go:${version}`,
		scope: IMAGE
	},
	linux: {
		purl: 'pkg:generic/linux',
		cpe: (version) => `cpe:2.3:o:linux:linux_kernel:${version}`,
		scope: IMAGE
	},
	ntpdRs: { purl: 'pkg:github/pendulum-project/ntpd-rs', scope: IMAGE },
	stogasVerifier: { purl: 'pkg:github/StogasAI/stogas', scope: IMAGE },
	svsm: { purl: 'pkg:github/coconut-svsm/svsm', scope: BUILD_TOOL },
	systemd: {
		purl: 'pkg:github/systemd/systemd',
		cpe: (version) => `cpe:2.3:a:systemd_project:systemd:${version}`,
		scope: IMAGE
	},
	virtFirmwareRs: { purl: 'pkg:gitlab/kraxel/virt-firmware-rs', scope: BUILD_TOOL }
};

const LOCKS = {
	'igvmmeasure.Cargo.lock': BUILD_TOOL,
	'ntpd-rs.Cargo.lock': IMAGE,
	'pdftext.Cargo.lock': IMAGE,
	'stogas-verifier.Cargo.lock': IMAGE,
	'virt-firmware-rs.Cargo.lock': BUILD_TOOL
};

// The version 5 UUID of a URL, from the namespace that RFC 9562 gives URLs. A package URL is one.
function urlUuid(url) {
	const namespace = Buffer.from('6ba7b8119dad11d180b400c04fd430c8', 'hex');
	const hash = createHash('sha1').update(namespace).update(url).digest();
	hash[6] = (hash[6] & 0x0f) | 0x50;
	hash[8] = (hash[8] & 0x3f) | 0x80;
	return hash.toString('hex', 0, 16).replace(/^(.{8})(.{4})(.{4})(.{4})/, '$1-$2-$3-$4-');
}

function sameKeys(table, names, label) {
	const known = Object.keys(table).sort().join(' ');
	const found = [...names].sort().join(' ');
	if (known !== found)
		throw new Error(`sbom.mjs names ${label} ${known}; the release has ${found}`);
}

export function bom(sourceRoot, { tag, commit, time }) {
	const release = join(sourceRoot, 'stogas/release');
	const read = (path) => readFileSync(join(sourceRoot, path), 'utf8');
	const components = new Map();
	const add = (purl, name, version, scope, extra = {}) => {
		// A crate that the image and a build tool share is part of the image.
		if (components.get(purl)?.scope === IMAGE) return;
		components.set(purl, {
			type: 'library',
			'bom-ref': purl,
			name,
			version,
			scope,
			purl,
			...extra
		});
	};

	const pins = JSON.parse(read('stogas/release/pins.lock.json')).releaseSources;
	sameKeys(SOURCES, Object.keys(pins), 'the pinned sources');
	for (const [name, pin] of Object.entries(pins)) {
		const { purl, cpe, scope } = SOURCES[name];
		const version = pin.version ?? pin.commit;
		// A package URL of a repository names the commit; every other kind names the version.
		const id =
			purl.startsWith('pkg:generic/') || purl.startsWith('pkg:golang/') ? pin.version : pin.commit;
		add(`${purl}@${id}`, purl.slice(purl.lastIndexOf('/') + 1), version, scope, {
			...(cpe && { cpe: `${cpe(pin.version)}:*:*:*:*:*:*:*` })
		});
	}

	const guix = read('stogas/release/guix/channels.scm').match(/\(commit "([0-9a-f]{40})"\)/)[1];
	add(`pkg:generic/guix@${guix}`, 'guix', guix, IMAGE, {
		type: 'platform',
		description:
			'Supplies the compiler, the C library, and every other build input that this file does not list.'
	});

	const locks = readdirSync(join(release, 'locks')).filter((file) => file.endsWith('.lock'));
	sameKeys(LOCKS, locks, 'the lockfiles');
	for (const lock of locks) {
		for (const block of read(`stogas/release/locks/${lock}`).split('[[package]]\n').slice(1)) {
			const field = (key) => block.match(new RegExp(`^${key} = "(.*)"$`, 'm'))?.[1];
			// The build refuses a Git crate that differs from its pinned source, which is listed above.
			if (field('source')?.startsWith('git+')) continue;
			const checksum = field('checksum');
			add(
				`pkg:cargo/${field('name')}@${field('version')}`,
				field('name'),
				field('version'),
				LOCKS[lock],
				{
					...(checksum && { hashes: [{ alg: 'SHA-256', content: checksum }] })
				}
			);
		}
	}

	// go.sum holds each module's hash as base64. CycloneDX takes hexadecimal.
	const sums = new Map(
		[...read('transports/go.sum').matchAll(/^(\S+) (\S+) h1:(\S+)$/gm)].map(
			([, path, version, hash]) => [
				`${path} ${version}`,
				Buffer.from(hash, 'base64').toString('hex')
			]
		)
	);
	const transports = join(sourceRoot, 'transports');
	for (const section of read('transports/vendor/modules.txt').split(/^# /m).slice(1)) {
		const [header, ...lines] = section.split('\n');
		const [, path, version, newPath, newVersion] =
			header.match(/^(\S+) (v\S+)(?: => (\S+)(?: (v\S+))?)?$/) ?? [];
		// A module without a package line is required and not built.
		if (!path || !lines.some((line) => line && !line.startsWith('#'))) continue;
		// A module that the source replaces with its own directory is part of the gateway itself.
		if (
			newPath &&
			!newVersion &&
			!relative(sourceRoot, resolve(transports, newPath)).startsWith('..')
		)
			continue;
		const [name, at] = newVersion ? [newPath, newVersion] : [path, version];
		const hash = sums.get(`${name} ${at}`);
		add(`pkg:golang/${name}@${encodeURIComponent(at)}`, name, at, IMAGE, {
			...(hash && { hashes: [{ alg: 'SHA-256', content: hash }] })
		});
	}

	const gateway = `pkg:github/StogasAI/gateway@${commit}`;
	const sorted = [...components.keys()].sort();
	return {
		bomFormat: 'CycloneDX',
		specVersion: '1.6',
		// GitHub attests no CycloneDX file without a serial number. One that names the release
		// stays the same when the tag is built again.
		serialNumber: `urn:uuid:${urlUuid(`pkg:github/StogasAI/gateway@${tag}`)}`,
		version: 1,
		metadata: {
			timestamp: new Date(time * 1000).toISOString(),
			supplier: { name: 'Stogas' },
			component: {
				type: 'application',
				'bom-ref': gateway,
				name: 'stogas-gateway',
				version: tag,
				purl: gateway
			}
		},
		components: sorted.map((purl) => components.get(purl)),
		dependencies: [{ ref: gateway, dependsOn: sorted }]
	};
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	const sourceRoot = process.argv[2];
	const {
		STOGAS_RELEASE_TAG: tag,
		STOGAS_RELEASE_COMMIT: commit,
		STOGAS_RELEASE_TIME: time
	} = process.env;
	if (process.argv.length !== 3 || !existsSync(sourceRoot) || !tag || !commit || !time)
		throw new Error(
			'usage: STOGAS_RELEASE_TAG, STOGAS_RELEASE_COMMIT and STOGAS_RELEASE_TIME set; sbom.mjs <gateway-source>'
		);
	process.stdout.write(
		`${JSON.stringify(bom(resolve(sourceRoot), { tag, commit, time }), null, 2)}\n`
	);
}
