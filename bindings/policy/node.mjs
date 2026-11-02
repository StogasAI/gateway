import { readFileSync } from 'node:fs';
import { createPolicyCompiler } from './compiler.mjs';

let module;
let compiler;

export function inspectPolicy(request) {
	module ??= new WebAssembly.Module(
		readFileSync(new URL('../../dist/stogas-policy.wasm', import.meta.url))
	);
	compiler ??= createPolicyCompiler(module);
	try {
		return compiler.inspect(request);
	} catch (error) {
		// A trap leaves the Go runtime unusable, so the next call starts a new instance.
		compiler = undefined;
		throw error;
	}
}
