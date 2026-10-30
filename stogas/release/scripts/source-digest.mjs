import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// Every Stogas release identifies a directory by the SHA-256 of the canonical
// JSON list of its files' paths, executable modes and SHA-256 digests, sorted
// by path. Directories and timestamps are not part of the identity.
export function sourceDigest(directory) {
	const entries = [];
	const refuse = (relative) => new Error(`Source contains a link or special file: ${relative}`);
	const visit = (path, prefix) => {
		for (const entry of readdirSync(path, { withFileTypes: true })) {
			const child = join(path, entry.name);
			const relative = prefix + entry.name;
			if (entry.isDirectory()) {
				visit(child, `${relative}/`);
				continue;
			}
			if (!entry.isFile()) throw refuse(relative);
			// Check and read the same open file, so a file replaced by a link or special file after
			// the listing is refused rather than followed.
			let descriptor;
			try {
				descriptor = openSync(
					child,
					constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0)
				);
			} catch (error) {
				if (error?.code === 'ELOOP' || error?.code === 'EMLINK') throw refuse(relative);
				throw error;
			}
			try {
				const stat = fstatSync(descriptor);
				if (!stat.isFile()) throw refuse(relative);
				entries.push({
					mode: stat.mode & 0o111 ? 0o755 : 0o644,
					path: relative,
					sha256: createHash('sha256').update(readFileSync(descriptor)).digest('hex')
				});
			} finally {
				closeSync(descriptor);
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
