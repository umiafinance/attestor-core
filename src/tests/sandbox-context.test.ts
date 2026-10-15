import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { it } from 'node:test'

import { assertSupportedInputContext, assertSupportedSignedContext } from '#src/server/utils/claim-context-policy.ts'
import { TEST_CHAIN_IDS, TEST_IDENTITY_PROVIDER, TEST_PROVIDER_HASH, TEST_SESSION_ID, testAuthIdentity } from '#src/tests/utils/claim-context.ts'

// Byte-equal to @umia/types proof-context.sandbox-vectors.json; a repo test enforces it.
const vectors = JSON.parse(
	readFileSync(new URL('./fixtures/sandbox-context-vectors.json', import.meta.url), 'utf8')
) as { chainId: number, contextAddress: string, accepted: string[], rejected: string[] }

function input(contextMessage: string, contextAddress = vectors.contextAddress) {
	return JSON.stringify({ contextAddress, contextMessage, identityProvider: TEST_IDENTITY_PROVIDER, reclaimSessionId: TEST_SESSION_ID })
}

it('admits exactly the shared sandbox context vectors as sandbox messages', () => {
	assert.equal(vectors.chainId, 10143)
	for(const message of vectors.accepted) {
		assert.equal(assertSupportedInputContext(input(message), testAuthIdentity(message, vectors.contextAddress), TEST_CHAIN_IDS).contextMessage, message)
	}
	// A rejected vector may still be a valid auction message; it must never pass as a sandbox one.
	for(const message of vectors.rejected) {
		let admitted = true
		try {
			assertSupportedInputContext(input(message), testAuthIdentity(message, vectors.contextAddress), TEST_CHAIN_IDS)
		} catch {
			admitted = false
		}
		assert.ok(!admitted || /^(register|bid):/.test(message), message)
	}
})

it('admits a sandbox context bound to its wallet and session through both checks', () => {
	const message = vectors.accepted[0]
	const accepted = assertSupportedInputContext(input(message), testAuthIdentity(message, vectors.contextAddress), TEST_CHAIN_IDS)
	assertSupportedSignedContext(JSON.stringify({
		contextAddress: vectors.contextAddress, contextMessage: message,
		extractedParameters: { handle: 'synthetic' },
		identityProvider: TEST_IDENTITY_PROVIDER,
		providerHash: TEST_PROVIDER_HASH, reclaimSessionId: TEST_SESSION_ID
	}), accepted)
})

it('rejects a sandbox context for another wallet, another session, or free text', () => {
	const other = '0x00000000000000000000000000000000000000a2'
	for(const [raw, session] of [
		[input(vectors.accepted[0], other), TEST_SESSION_ID],
		[input(vectors.accepted[0]), 'different-session'],
		[input('Auction verification'), TEST_SESSION_ID],
		[input('test-only sandbox run:alpha'), TEST_SESSION_ID],
	]) {
		assert.throws(() => assertSupportedInputContext(raw, testAuthIdentity(vectors.accepted[0], vectors.contextAddress, session), TEST_CHAIN_IDS), /Unsupported claim context/)
	}
})

it('refuses modified namespace, wallet, challenge, provider hash, and replayed session', () => {
	const message = vectors.accepted[0]
	const binding = testAuthIdentity(message, vectors.contextAddress)
	const valid = JSON.parse(input(message))
	for(const changed of [
		{ identityProvider: 'other' },
		{ contextAddress: '0x00000000000000000000000000000000000000a2' },
		{ contextMessage: vectors.accepted[1] },
		{ reclaimSessionId: 'replayed-session' }
	]) {
		assert.throws(() => assertSupportedInputContext(JSON.stringify({ ...valid, ...changed }), binding, TEST_CHAIN_IDS))
	}
	const accepted = assertSupportedInputContext(input(message), binding, TEST_CHAIN_IDS)
	const claim = {
		...valid, extractedParameters: { account: 'stable' }, providerHash: TEST_PROVIDER_HASH
	}
	assert.throws(() => assertSupportedSignedContext(JSON.stringify({ ...claim, providerHash: `0x${'b'.repeat(64)}` }), accepted))
})
