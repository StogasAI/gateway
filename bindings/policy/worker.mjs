import module from '../../dist/stogas-policy.wasm';
import { createPolicyCompiler } from './compiler.mjs';

let compiler;

export function inspectPolicy(request) {
	compiler ??= createPolicyCompiler(module);
	try {
		return compiler.inspect(request);
	} catch (error) {
		// A trap leaves the Go runtime unusable, so the next call starts a new instance.
		compiler = undefined;
		throw error;
	}
}
