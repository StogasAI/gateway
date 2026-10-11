import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('tree-sha256.sh', import.meta.url));
const hash = (tree) => execFileSync(script, [tree], { encoding: 'utf8', stdio: 'pipe' }).trim();

test('tree hashes cover file content, executable bits and empty directories', (t) => {
	const root = mkdtempSync(join(tmpdir(), 'tree-sha256-'));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	const tree = (name) => {
		const directory = join(root, name);
		mkdirSync(join(directory, 'empty'), { recursive: true });
		writeFileSync(join(directory, 'input'), 'pinned input\n', { mode: 0o644 });
		return directory;
	};
	const expected = hash(tree('first'));
	const second = tree('second');
	assert.equal(hash(second), expected);

	writeFileSync(join(second, 'input'), 'changed input\n');
	assert.notEqual(hash(second), expected);
	writeFileSync(join(second, 'input'), 'pinned input\n');

	chmodSync(join(second, 'input'), 0o755);
	assert.notEqual(hash(second), expected);
	chmodSync(join(second, 'input'), 0o644);

	mkdirSync(join(second, 'extra'));
	assert.notEqual(hash(second), expected);
});

test('tree hashes reject symbolic links', (t) => {
	const root = mkdtempSync(join(tmpdir(), 'tree-sha256-'));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	writeFileSync(join(root, 'input'), 'pinned input\n');
	symlinkSync('input', join(root, 'link'));
	assert.throws(() => hash(root));
});
