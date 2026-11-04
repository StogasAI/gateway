import assert from 'node:assert/strict';
import test from 'node:test';
import { inspectPolicy } from './node.mjs';

test('the JavaScript binding preserves Unicode and recovers after a rejected document', () => {
	assert.equal(inspectPolicy({ source: { version: 2 } }).error.status, 400);
	const source = {
		plugins: { redaction: { literals: [{ values: ['Žmogus', '日本語', '🛰️'] }] } }
	};
	const first = inspectPolicy({ source });
	assert.ok(!first.error);
	assert.deepEqual(
		new Set(first.compiled.plugins.redaction.literals.map((item) => item.text)),
		new Set(['Žmogus', '日本語', '🛰️'])
	);
	assert.deepEqual(inspectPolicy({ source }), first);
	assert.equal(inspectPolicy({ source, unknown: true }).error.status, 400);
	assert.equal(inspectPolicy({ source, operation: 'finish' }).error.status, 400);
	assert.deepEqual(inspectPolicy({ source }), first);
});

test('opaque plugins survive the memory bridge in their original order', () => {
	const envelope = (byte, length = 200_000) => ({
		version: 1,
		keyId: 'a'.repeat(64),
		salt: Buffer.alloc(32, byte).toString('base64url'),
		nonce: Buffer.alloc(12).toString('base64url'),
		blob: Buffer.alloc(length, byte).toString('base64url')
	});
	const sources = [
		{
			scope: 'organization',
			config: { encryption: { keys: { default: 'a'.repeat(64) } } }
		},
		...[1, 2, 1].map((byte, index) => ({
			scope: 'role',
			config: {
				routing: { filter: `model.id != 'blocked-${index}'` },
				// Inspection reports a policy's export before its redaction.
				plugins: {
					redaction: { encrypted: envelope(byte) },
					...(index === 1 && { textExtraction: true, export: { encrypted: envelope(4, 1000) } })
				}
			}
		})),
		{ scope: 'key', config: {} }
	];
	for (let repeat = 0; repeat < 3; repeat++) {
		const result = inspectPolicy({ sources });
		assert.ok(!result.error);
		assert.deepEqual(
			result.effective.uncheckedPlugins.map((item) => [item.plugin, item.encrypted]),
			[
				['redaction', envelope(1)],
				['export', envelope(4, 1000)],
				['redaction', envelope(2)],
				['redaction', envelope(1)]
			]
		);
		assert.equal(result.effective.plugins.textExtraction, true);
		result.effective.uncheckedPlugins[0].encrypted.blob = 'changed';
		assert.equal(sources[1].config.plugins.redaction.encrypted.blob, envelope(1).blob);
	}
});

test('the JavaScript binding returns combined policies and typed edit failures', () => {
	const sources = [
		{ scope: 'organization', config: { delegation: { keys: false } } },
		{ scope: 'key', id: 'key', config: { input: { asciiOnly: true } } }
	];
	const result = inspectPolicy({ sources });
	assert.equal(result.effective.input.asciiOnly, true);
	assert.equal(result.effective.delegation.keys, false);
	assert.equal(
		inspectPolicy({ sources, edit: { scope: 'key', id: 'key', previous: {} } }).error.status,
		403
	);
	const kept = inspectPolicy({
		sources,
		edit: { scope: 'key', id: 'key', previous: sources[1].config }
	});
	assert.deepEqual(kept.notes, [{ kind: 'kept', scope: 'organization', sections: ['input'] }]);
});

test('conditional opaque rules preserve their source identity without retaining output aliases', () => {
	const envelope = (byte) => ({
		version: 1,
		keyId: 'b'.repeat(64),
		salt: Buffer.alloc(32, byte).toString('base64url'),
		nonce: Buffer.alloc(12).toString('base64url'),
		blob: Buffer.alloc(200_000, byte).toString('base64url')
	});
	const sources = [
		{
			scope: 'organization',
			config: { encryption: { keys: { rules: 'b'.repeat(64) } } }
		},
		...[1, 2].map((byte) => ({
			scope: 'role',
			id: String(byte),
			config: {
				rules: {
					z_opaque: {
						when: "provider.id == 'openai'",
						plugins: { textExtraction: true, redaction: { encrypted: envelope(byte) } }
					},
					a_plain: { input: { asciiOnly: true } }
				}
			}
		})),
		{ scope: 'key', config: {} }
	];
	const first = inspectPolicy({ sources });
	assert.ok(!first.error);
	assert.deepEqual(
		first.effective.rules.map((rule) => [rule.policy.id, rule.name]),
		[
			['1', 'a_plain'],
			['1', 'z_opaque'],
			['2', 'a_plain'],
			['2', 'z_opaque']
		]
	);
	assert.deepEqual(
		first.effective.rules
			.filter((rule) => rule.name === 'z_opaque')
			.map((rule) => rule.config.plugins),
		[1, 2].map((byte) => ({ textExtraction: true, redaction: { encrypted: envelope(byte) } }))
	);
	first.effective.rules[1].config.plugins.redaction.encrypted.blob = 'changed';
	assert.equal(sources[1].config.rules.z_opaque.plugins.redaction.encrypted.blob, envelope(1).blob);
	assert.equal(inspectPolicy({ sources }).digest, first.digest);
	const changed = structuredClone(sources);
	changed[1].config.rules.z_opaque.plugins.redaction.encrypted.blob = envelope(3).blob;
	assert.notEqual(inspectPolicy({ sources: changed }).digest, first.digest);
});

test('a rule whose only setting is the default ordering shows in routing.sort, not in rules', () => {
	const envelope = (byte) => ({
		version: 1,
		keyId: 'c'.repeat(64),
		salt: Buffer.alloc(32, byte).toString('base64url'),
		nonce: Buffer.alloc(12).toString('base64url'),
		blob: Buffer.alloc(1000, byte).toString('base64url')
	});
	const opaque = (byte) => ({
		when: "provider.id == 'openai'",
		plugins: { textExtraction: true, redaction: { encrypted: envelope(byte) } }
	});
	const sources = [
		{
			scope: 'organization',
			config: {
				encryption: { keys: { rules: 'c'.repeat(64) } },
				rules: {
					a_order: { mode: 'default', routing: { sort: [{ by: 'provider.id' }] } },
					z_opaque: opaque(1)
				}
			}
		},
		{ scope: 'role', id: '2', config: { rules: { z_opaque: opaque(2) } } },
		{ scope: 'key', config: {} }
	];
	const result = inspectPolicy({ sources });
	assert.ok(!result.error, result.error?.message);
	assert.deepEqual(
		result.effective.routing.sortFrom.map((item) => [item.policy.scope, item.rule]),
		[['organization', 'a_order']]
	);
	// Each opaque rule keeps its own envelope although the ordering rule before it is left out.
	assert.deepEqual(
		result.effective.rules.map((rule) => [
			rule.policy.scope,
			rule.name,
			rule.config.plugins.redaction.encrypted
		]),
		[
			['organization', 'z_opaque', envelope(1)],
			['role', 'z_opaque', envelope(2)]
		]
	);
});

test('a compiler that traps is replaced on the next call without compiling the module again', () => {
	const source = { input: { asciiOnly: true } };
	const expected = inspectPolicy({ source });
	// An input past the limit fails before the compiler reads it, and the next call starts afresh.
	assert.throws(() => inspectPolicy({ source: { padding: 'x'.repeat(1 << 20) } }), /input limit/);
	const { Instance, Module } = WebAssembly;
	let instances = 0;
	let modules = 0;
	// The first new instance traps as a Go panic does, and every later call into it fails too.
	WebAssembly.Instance = function (module, imports) {
		const instance = new Instance(module, imports);
		if (++instances > 1) return instance;
		let trapped = false;
		const trap =
			(name) =>
			(...args) => {
				if (trapped || name === 'inspect') {
					trapped = true;
					throw new WebAssembly.RuntimeError('unreachable');
				}
				return instance.exports[name](...args);
			};
		const exports = { ...instance.exports };
		for (const name of ['allocate', 'inspect', 'release']) exports[name] = trap(name);
		return { exports };
	};
	WebAssembly.Module = function (...args) {
		modules += 1;
		return new Module(...args);
	};
	try {
		assert.throws(() => inspectPolicy({ source }), WebAssembly.RuntimeError);
		assert.deepEqual(inspectPolicy({ source }), expected);
		assert.equal(instances, 2);
		assert.equal(modules, 0);
	} finally {
		WebAssembly.Instance = Instance;
		WebAssembly.Module = Module;
	}
});
