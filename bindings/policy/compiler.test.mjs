import assert from 'node:assert/strict';
import test from 'node:test';
import { inspectPolicy } from './node.mjs';

test('the JavaScript binding preserves Unicode and recovers after a rejected document', () => {
	assert.equal(inspectPolicy({ source: { version: 2 } }).error.status, 400);
	const source = {
		plugins: { stogasRedaction: { literals: [{ values: ['Žmogus', '日本語', '🛰️'] }] } }
	};
	const first = inspectPolicy({ source });
	assert.ok(!first.error);
	assert.deepEqual(
		new Set(first.compiled.plugins.stogasRedaction.literals.map((item) => item.text)),
		new Set(['Žmogus', '日本語', '🛰️'])
	);
	assert.deepEqual(inspectPolicy({ source }), first);
	assert.equal(inspectPolicy({ source, unknown: true }).error.status, 400);
	assert.equal(inspectPolicy({ source, operation: 'finish' }).error.status, 400);
	assert.deepEqual(inspectPolicy({ source }), first);
});

test('opaque sections survive the memory bridge in their original order', () => {
	const envelope = (byte) => ({
		version: 1,
		keyId: 'a'.repeat(64),
		salt: Buffer.alloc(32, byte).toString('base64url'),
		nonce: Buffer.alloc(12).toString('base64url'),
		blob: Buffer.alloc(200_000, byte).toString('base64url')
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
				plugins: { encrypted: envelope(byte) }
			}
		})),
		{ scope: 'key', config: {} }
	];
	for (let repeat = 0; repeat < 3; repeat++) {
		const result = inspectPolicy({ sources });
		assert.ok(!result.error);
		assert.deepEqual(
			result.effective.uncheckedPlugins.map((item) => item.encrypted),
			[envelope(1), envelope(2), envelope(1)]
		);
		result.effective.uncheckedPlugins[0].encrypted.blob = 'changed';
		assert.equal(sources[1].config.plugins.encrypted.blob, envelope(1).blob);
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
					z_opaque: { when: "provider.id == 'openai'", plugins: { encrypted: envelope(byte) } },
					a_plain: { input: { asciiOnly: true } }
				}
			}
		})),
		{ scope: 'key', config: {} }
	];
	const first = inspectPolicy({ sources });
	assert.ok(!first.error);
	assert.deepEqual(
		first.effective.rules.map((rule) => [rule.id, rule.name]),
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
			.map((rule) => rule.config.plugins.encrypted),
		[envelope(1), envelope(2)]
	);
	first.effective.rules[1].config.plugins.encrypted.blob = 'changed';
	assert.equal(sources[1].config.rules.z_opaque.plugins.encrypted.blob, envelope(1).blob);
	assert.equal(inspectPolicy({ sources }).digest, first.digest);
	const changed = structuredClone(sources);
	changed[1].config.rules.z_opaque.plugins.encrypted.blob = envelope(3).blob;
	assert.notEqual(inspectPolicy({ sources: changed }).digest, first.digest);
});
