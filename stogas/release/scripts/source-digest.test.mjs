import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { sourceDigest } from './source-digest.mjs';

function fixture(t) {
	const root = mkdtempSync(join(tmpdir(), 'source-digest-'));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	mkdirSync(join(root, 'dir'));
	mkdirSync(join(root, 'empty'));
	writeFileSync(join(root, 'a'), 'first');
	chmodSync(join(root, 'a'), 0o755);
	writeFileSync(join(root, 'dir.txt'), '');
	writeFileSync(join(root, 'dir', 'z'), Buffer.from('payload\0\xff', 'latin1'));
	return root;
}

test('source digests match the shared release identity', (t) => {
	const root = fixture(t);
	// The same value the verifier and catalog release tooling compute.
	assert.equal(
		sourceDigest(root),
		'887904a1ae03e4449f05e05fb147314cf9c8c428d3eec00179e0d7f56fc3a853'
	);
	chmodSync(join(root, 'a'), 0o644);
	assert.notEqual(
		sourceDigest(root),
		'887904a1ae03e4449f05e05fb147314cf9c8c428d3eec00179e0d7f56fc3a853'
	);
});

test('source digests reject links', (t) => {
	const root = fixture(t);
	symlinkSync('a', join(root, 'link'));
	assert.throws(() => sourceDigest(root), /link or special file: link/);
});
