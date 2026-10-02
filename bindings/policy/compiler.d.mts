/** Create an isolated, synchronous compiler from the policy WASI module. */
export function createPolicyCompiler(module: WebAssembly.Module): {
	inspect(request: unknown): unknown;
};
