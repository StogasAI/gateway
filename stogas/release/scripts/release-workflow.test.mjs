import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

const workflow = readFileSync(
	new URL('../../../.github/workflows/gateway-igvm-release.yml', import.meta.url),
	'utf8'
);

for (const job of ['build', 'publish']) {
	const definition = workflow.split(`  ${job}:\n`)[1]?.split(/\n {2}\w+:\n/)[0];
	const refInput = definition?.match(/^ {10}ref: \$\{\{ github\.(\w+) \}\}$/m)?.[1];
	// Execute the workflow's shell gate, rather than a second copy of its checks.
	const gate = definition
		?.match(/^ {6}- name: Verify checked-out tag\n {8}run: \|\n((?: {10}.*\n)+)/m)?.[1]
		.replace(/^ {10}/gm, '');
	assert.ok(refInput && gate, `${job} must define its checkout ref and tag verification`);

	for (const annotated of [false, true]) {
		test(`${job} binds ${annotated ? 'annotated' : 'lightweight'} release tags to the event commit despite a colliding branch`, (t) => {
			const repository = mkdtempSync(join(tmpdir(), 'release-ref-'));
			t.after(() => rmSync(repository, { recursive: true, force: true }));
			const env = {
				...process.env,
				GIT_CONFIG_NOSYSTEM: '1',
				GIT_CONFIG_GLOBAL: '/dev/null',
				GIT_AUTHOR_NAME: 'Release test',
				GIT_AUTHOR_EMAIL: 'release-test@example.invalid',
				GIT_COMMITTER_NAME: 'Release test',
				GIT_COMMITTER_EMAIL: 'release-test@example.invalid'
			};
			const git = (...args) =>
				execFileSync('git', args, { cwd: repository, env, encoding: 'utf8', stdio: 'pipe' }).trim();
			git('init', '--quiet', '--initial-branch=source');
			git('commit', '--quiet', '--allow-empty', '-m', 'Release source');
			const releaseCommit = git('rev-parse', 'HEAD');
			const tag = 'v1.2.3';
			git('tag', ...(annotated ? ['-a', '-m', 'Release tag'] : []), tag);
			git('commit', '--quiet', '--allow-empty', '-m', 'Unrelated branch source');
			const branchCommit = git('rev-parse', 'HEAD');
			git('branch', tag);

			const event = { ref: `refs/tags/${tag}`, ref_name: tag, sha: releaseCommit };
			assert.ok(event[refInput], `${job} uses a supported event ref`);
			git('checkout', '--quiet', event[refInput]);
			assert.equal(git('rev-parse', 'HEAD'), releaseCommit);
			const verify = () =>
				spawnSync('bash', ['-c', gate], {
					cwd: repository,
					env: { ...env, GITHUB_REF: event.ref, GITHUB_REF_NAME: tag, GITHUB_SHA: releaseCommit },
					encoding: 'utf8'
				});
			const accepted = verify();
			assert.equal(accepted.status, 0, accepted.stderr);

			git('checkout', '--quiet', `refs/heads/${tag}`);
			assert.notEqual(verify().status, 0, 'A branch checkout must not pass the tag gate');
			git('tag', '--force', ...(annotated ? ['-a', '-m', 'Moved tag'] : []), tag, branchCommit);
			assert.notEqual(verify().status, 0, 'A moved tag must not replace the event commit');
		});
	}
}
