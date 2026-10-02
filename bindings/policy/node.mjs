import { readFileSync } from 'node:fs';
import { createPolicyCompiler } from './compiler.mjs';

let compiler;

export function inspectPolicy(request) {
	compiler ??= createPolicyCompiler(
		new WebAssembly.Module(readFileSync(new URL('../../dist/stogas-policy.wasm', import.meta.url)))
	);
	return compiler.inspect(request);
}
