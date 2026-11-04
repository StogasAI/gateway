import { WASI, File, OpenFile, ConsoleStdout } from '@bjorn3/browser_wasi_shim';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

// The plugins a customer key can encrypt, in the order inspection reports them.
const encryptablePlugins = ['export', 'redaction'];
const encryptedPlugins = (plugins) =>
	encryptablePlugins.flatMap((name) =>
		plugins?.[name]?.encrypted ? [{ name, envelope: plugins[name].encrypted }] : []
	);

// Initialization is explicit so hosts can create the compiler inside their
// request context. The WASI instance has no files, environment or network.
export function createPolicyCompiler(module) {
	const discard = () => {};
	const wasi = new WASI(
		[],
		[],
		[
			new OpenFile(new File(new Uint8Array())),
			new ConsoleStdout(discard),
			new ConsoleStdout(discard)
		],
		{ debug: false }
	);
	const instance = new WebAssembly.Instance(module, { wasi_snapshot_preview1: wasi.wasiImport });
	wasi.initialize(instance);
	const { allocate, inspect, release, memory } = instance.exports;
	function call(request) {
		const bytes = encoder.encode(JSON.stringify(request));
		const pointer = allocate(bytes.length);
		if (!pointer) throw new Error('Policy inspection exceeds its input limit');
		new Uint8Array(memory.buffer, pointer, bytes.length).set(bytes);
		const result = inspect();
		const offset = Number(result >> 32n);
		const length = Number(result & 0xffffffffn);
		return JSON.parse(decoder.decode(new Uint8Array(memory.buffer, offset, length)));
	}
	return {
		inspect(request) {
			try {
				if (!request || typeof request !== 'object') return call({ operation: 'invalid' });
				if (Object.hasOwn(request, 'operation') || Object.hasOwn(request, 'item'))
					return call({ operation: 'invalid' });
				if (!Array.isArray(request.sources)) return call({ ...request, operation: 'source' });
				const { sources, ...header } = request;
				const begin = call({ ...header, operation: 'begin' });
				if (begin?.error) return begin;
				for (const item of sources) {
					const next = call({ operation: 'append', item });
					if (next?.error) return next;
				}
				const result = call({ operation: 'finish' });
				const rules = result.effective?.rules;
				if (rules) {
					const originals = sources.flatMap((source) =>
						Object.keys(source.config.rules ?? {})
							.sort()
							.map((name) => ({ source, name, config: source.config.rules[name] }))
					);
					let next = 0;
					for (const original of originals) {
						const rule = rules[next];
						const envelopes = encryptedPlugins(original.config.plugins);
						if (
							rule?.name !== original.name ||
							rule.policy?.scope !== original.source.scope ||
							(rule.policy?.id ?? '') !== (original.source.id ?? '')
						) {
							// Inspection leaves out a rule whose only setting is the default
							// ordering, which routing.sort shows. Such a rule has no plugins.
							if (envelopes.length)
								throw new Error('Policy inspection returned invalid rule references');
							continue;
						}
						next += 1;
						for (const { name, envelope } of envelopes) {
							const plugin = rule.config?.plugins?.[name];
							if (!plugin || !Object.hasOwn(plugin, 'encrypted'))
								throw new Error('Policy inspection returned invalid rule references');
							plugin.encrypted = { ...envelope };
						}
					}
					if (next !== rules.length)
						throw new Error('Policy inspection returned invalid rule references');
				}
				const opaque = result.effective?.uncheckedPlugins;
				if (opaque) {
					const envelopes = sources.flatMap((source) => encryptedPlugins(source.config.plugins));
					if (opaque.length !== envelopes.length)
						throw new Error('Policy inspection returned invalid opaque references');
					for (const [index, item] of opaque.entries()) {
						if (item.plugin !== envelopes[index].name)
							throw new Error('Policy inspection returned invalid opaque references');
						item.encrypted = { ...envelopes[index].envelope };
					}
				}
				return result;
			} finally {
				release();
			}
		}
	};
}
