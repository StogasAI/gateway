import module from '../../dist/stogas-policy.wasm';
import { createPolicyCompiler } from './compiler.mjs';

let compiler;

export function inspectPolicy(request) {
	compiler ??= createPolicyCompiler(module);
	return compiler.inspect(request);
}
