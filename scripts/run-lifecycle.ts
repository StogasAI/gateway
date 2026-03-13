#!/usr/bin/env bun

import { rmSync } from 'node:fs';
import { join } from 'node:path';
import {
	API_APP_ROOT,
	API_BINARY_PATH,
	API_CHECK_BINARY_PATH,
	API_DATA_DIR,
	API_TRANSPORTS_DIR,
	buildApiGatewayBinary,
	ensureApiDirectories,
	ensureApiWorkspace,
	runApiGateway
} from '../../../scripts/lib/api-gateway';
import { runCommand } from '../../../scripts/lib/run';

const command = process.argv[2];

function cleanPaths(relativePaths: string[]) {
	for (const relativePath of relativePaths) {
		rmSync(join(API_APP_ROOT, relativePath), { force: true, recursive: true });
	}
}

try {
	switch (command) {
		case 'build':
			await buildApiGatewayBinary(API_BINARY_PATH);
			break;
		case 'check':
			await buildApiGatewayBinary(API_CHECK_BINARY_PATH);
			break;
		case 'clean':
			cleanPaths([
				'bifrost-data',
				'go.work',
				'go.work.sum',
				'tmp/.check-bifrost-http',
				'tmp/.check-bifrost-http.exe',
				'tmp/stogas-bifrost-http',
				'tmp/stogas-bifrost-http.exe',
				'tmp/bifrost-http',
				'tmp/bifrost-http.exe'
			]);
			break;
		case 'dev':
			await ensureApiWorkspace();
			ensureApiDirectories(['bifrost-data', 'tmp']);
			await runCommand(
				[
					'go',
					'run',
					'./bifrost-http',
					'-host',
					'127.0.0.1',
					'-port',
					process.env.API_PORT ?? '5185',
					'-app-dir',
					API_DATA_DIR,
					'-log-style',
					'pretty',
					'-log-level',
					process.env.LOG_LEVEL ?? 'info'
				],
				{ cwd: API_TRANSPORTS_DIR }
			);
			break;
		case 'preview':
			await buildApiGatewayBinary(API_BINARY_PATH);
			await runApiGateway({ binaryPath: API_BINARY_PATH, logLevel: 'info', logStyle: 'pretty' });
			break;
		default:
			throw new Error(`Unknown lifecycle command: ${command ?? '(missing)'}`);
	}
} catch (error) {
	console.error(`❌ ${error instanceof Error ? error.message : String(error)}`);
	process.exit(1);
}
