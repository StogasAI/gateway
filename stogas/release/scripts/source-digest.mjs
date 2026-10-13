import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// Every Stogas release identifies a directory by the SHA-256 of the canonical
// JSON list of its files' paths, executable modes and SHA-256 digests, sorted
// by path. Directories and timestamps are not part of the identity.
export function sourceDigest(directory) {
	const entries = [];
	const visit = (path, prefix) => {
		for (const name of readdirSync(path)) {
			const child = join(path, name);
			const relative = prefix + name;
			const stat = lstatSync(child);
			if (stat.isDirectory()) {
				visit(child, `${relative}/`);
			} else if (stat.isFile()) {
				entries.push({
					mode: stat.mode & 0o111 ? 0o755 : 0o644,
					path: relative,
					sha256: createHash('sha256').update(readFileSync(child)).digest('hex')
				});
			} else {
				throw new Error(`Source contains a link or special file: ${relative}`);
			}
		}
	};
	visit(resolve(directory), '');
	entries.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
	return createHash('sha256').update(JSON.stringify(entries)).digest('hex');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	if (process.argv.length !== 3 || !process.argv[2])
		throw new Error('usage: source-digest.mjs <directory>');
	console.log(sourceDigest(process.argv[2]));
}
