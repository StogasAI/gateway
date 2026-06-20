#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const TUF_BASE_URL = 'https://tuf-repo-cdn.sigstore.dev';
const TRUSTED_ROOT_TARGET_URL =
	'https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json';
const BOOTSTRAP_ROOT_VERSION = 10;

const output = resolve(process.argv[2] ?? 'sigstore-trust-bundle.json');

async function fetchText(url) {
	const response = await fetch(url, { headers: { accept: 'application/json' } });
	if (!response.ok) throw new Error(`Fetch ${url}: ${response.status}`);
	return response.text();
}

async function fetchRootChain() {
	const roots = [];
	for (let version = BOOTSTRAP_ROOT_VERSION; version < 64; version += 1) {
		const response = await fetch(`${TUF_BASE_URL}/${version}.root.json`, {
			headers: { accept: 'application/json' }
		});
		if (response.status === 404) break;
		if (!response.ok) throw new Error(`Fetch Sigstore TUF root ${version}: ${response.status}`);
		roots.push(await response.text());
	}
	if (roots.length === 0) throw new Error('No Sigstore TUF roots fetched.');
	return roots;
}

function metadataVersion(text, child) {
	const metadata = JSON.parse(text);
	const version = Number(metadata.signed?.meta?.[child]?.version);
	if (!Number.isSafeInteger(version)) {
		throw new Error(`Sigstore TUF metadata does not name ${child}.`);
	}
	return version;
}

const rootChain = await fetchRootChain();
const timestamp = await fetchText(`${TUF_BASE_URL}/timestamp.json`);
const snapshot = await fetchText(`${TUF_BASE_URL}/${metadataVersion(timestamp, 'snapshot.json')}.snapshot.json`);
const targets = await fetchText(`${TUF_BASE_URL}/${metadataVersion(snapshot, 'targets.json')}.targets.json`);
const trustedRoot = await fetchText(TRUSTED_ROOT_TARGET_URL);

mkdirSync(dirname(output), { recursive: true });
writeFileSync(
	output,
	`${JSON.stringify(
		{
			metadata: { snapshot, targets, timestamp },
			rootChain,
			schema: 'sigstore.tuf.trust.v1',
			trustedRoot
		},
		null,
		2
	)}\n`
);

console.log(`Wrote ${output}`);
