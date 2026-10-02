import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { snapshotSource } from './snapshot-source.mjs';

function fixture(t) {
	const directory = mkdtempSync(join(tmpdir(), 'source-capture-'));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	const repository = join(directory, 'repository');
	execFileSync('git', ['init', '-q', repository]);
	writeFileSync(join(repository, '.gitignore'), 'ignored\n');
	writeFileSync(join(repository, 'tracked'), 'original');
	execFileSync('git', ['-C', repository, 'add', '.']);
	return { directory, repository };
}

test('captures edits and new source, excludes ignored files, and remains independent', (t) => {
	const { directory, repository } = fixture(t);
	writeFileSync(join(repository, 'tracked'), 'captured');
	writeFileSync(join(repository, 'new'), 'new source');
	writeFileSync(join(repository, 'ignored'), 'not build input');
	const destination = join(directory, 'snapshot');
	assert.throws(() => snapshotSource(repository, destination), /clean worktree/);
	snapshotSource(repository, destination, true);
	writeFileSync(join(repository, 'tracked'), 'later edit');
	assert.equal(readFileSync(join(destination, 'tracked'), 'utf8'), 'captured');
	assert.equal(readFileSync(join(destination, 'new'), 'utf8'), 'new source');
	assert.throws(() => readFileSync(join(destination, 'ignored')), { code: 'ENOENT' });
	assert.throws(() => readFileSync(join(destination, '.git')), { code: 'ENOENT' });
});

test('omits deleted source and rejects links and an in-repository destination', (t) => {
	const { directory, repository } = fixture(t);
	rmSync(join(repository, 'tracked'));
	const destination = join(directory, 'snapshot');
	snapshotSource(repository, destination, true);
	assert.throws(() => readFileSync(join(destination, 'tracked')), { code: 'ENOENT' });
	assert.throws(() => snapshotSource(repository, join(repository, 'snapshot'), true), /outside/);
	symlinkSync(repository, join(directory, 'alias'));
	assert.throws(
		() => snapshotSource(repository, join(directory, 'alias/snapshot'), true),
		/outside/
	);
	symlinkSync(join(repository, '.gitignore'), join(repository, 'linked'));
	assert.throws(() => snapshotSource(repository, join(directory, 'linked-snapshot'), true), /link/);
});
