import { execFileSync } from 'node:child_process';
import { chmodSync, copyFileSync, lstatSync, mkdirSync, realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

// Capture tracked edits and non-ignored new files once. Both language builds
// consume this directory, never the changing checkout or its build caches.
export function snapshotSource(repository, destination, allowDirty = false) {
	const root = realpathSync(repository);
	const git = (...args) =>
		execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', maxBuffer: 16 << 20 });
	if (realpathSync(git('rev-parse', '--show-toplevel').trim()) !== root) {
		throw new Error('Source must be a repository root.');
	}
	if (!allowDirty && git('status', '--porcelain=v1', '--untracked-files=normal').trim()) {
		throw new Error(
			'Source snapshot requires a clean worktree or explicit dirty-build permission.'
		);
	}
	const target = resolve(realpathSync(dirname(resolve(destination))), basename(destination));
	const child = relative(root, target);
	if (child === '' || (!isAbsolute(child) && child !== '..' && !child.startsWith(`..${sep}`))) {
		throw new Error('Source snapshot must be outside its repository.');
	}
	mkdirSync(target);
	const files = new Set(
		git('ls-files', '-z', '--cached', '--others', '--exclude-standard').split('\0').filter(Boolean)
	);
	for (const file of [...files].sort()) {
		const source = resolve(root, file);
		let before;
		try {
			before = lstatSync(source, { bigint: true });
		} catch (error) {
			if (error.code === 'ENOENT') continue; // A tracked file deleted in the worktree.
			throw error;
		}
		if (!before.isFile() || !realpathSync(source).startsWith(root + sep)) {
			throw new Error('Source snapshot contains a link, submodule, or special file.');
		}
		const output = resolve(target, file);
		mkdirSync(dirname(output), { recursive: true });
		copyFileSync(source, output);
		chmodSync(output, (before.mode & 0o111n) === 0n ? 0o644 : 0o755);
		const after = lstatSync(source, { bigint: true });
		if (
			before.ino !== after.ino ||
			before.size !== after.size ||
			before.mtimeNs !== after.mtimeNs ||
			before.ctimeNs !== after.ctimeNs
		) {
			throw new Error('Source changed while being captured; retry the build.');
		}
	}
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	if (process.argv.length !== 4)
		throw new Error('usage: snapshot-source.mjs <repository> <destination>');
	snapshotSource(process.argv[2], process.argv[3], process.env.STOGAS_RELEASE_ALLOW_DIRTY === '1');
}
