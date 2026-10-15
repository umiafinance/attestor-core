import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { it } from 'node:test'

import { assertSupportedInputContext, assertSupportedSignedContext } from '#src/server/utils/claim-context-policy.ts'
import { inputContext, TEST_CHAIN_IDS, TEST_CONTEXT_ADDRESS, TEST_CONTEXT_MESSAGE, TEST_IDENTITY_PROVIDER, TEST_PROVIDER_HASH, TEST_SESSION_ID, testAuthIdentity } from '#src/tests/utils/claim-context.ts'

// Value-equal to @umia/types proof-context.extraction-key-vectors.json; a repo test enforces it.
const keys = JSON.parse(
	readFileSync(new URL('./fixtures/extracted-key-vectors.json', import.meta.url), 'utf8')
) as { accepted: string[], rejected: string[] }

function signed(key: string) {
	return JSON.stringify({
		contextAddress: TEST_CONTEXT_ADDRESS, contextMessage: TEST_CONTEXT_MESSAGE,
		extractedParameters: { [key]: 'synthetic' },
		identityProvider: TEST_IDENTITY_PROVIDER,
		providerHash: TEST_PROVIDER_HASH, reclaimSessionId: TEST_SESSION_ID
	})
}

it('signs exactly the shared extraction key vectors', () => {
	const input = assertSupportedInputContext(inputContext(), testAuthIdentity(), TEST_CHAIN_IDS)
	for(const key of keys.accepted) {
		assert.doesNotThrow(() => assertSupportedSignedContext(signed(key), input), key)
	}
	for(const key of keys.rejected) {
		assert.throws(() => assertSupportedSignedContext(signed(key), input), /Unsupported claim context/, key)
	}
})
