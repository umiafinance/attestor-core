import assert from 'node:assert/strict'
import { it, mock } from 'node:test'

import { providers } from '#src/providers/index.ts'
import { assertValidProviderTranscript } from '#src/server/utils/assert-valid-claim-request.ts'
import { assertSupportedInputContext, assertSupportedSignedContext } from '#src/server/utils/claim-context-policy.ts'
import { inputContext, TEST_CHAIN_IDS, TEST_CONTEXT_ADDRESS, TEST_CONTEXT_MESSAGE, TEST_SESSION_ID, testAuthIdentity } from '#src/tests/utils/claim-context.ts'

const logger = { info() {}, debug() {}, warn() {}, error() {} }
const parameters = JSON.stringify({
	url: 'https://api.example.com/path', method: 'GET',
	responseMatches: [{ type: 'contains', value: 'synthetic-ok' }]
})

function claim() {
	return {
		provider: 'http', parameters, context: inputContext(),
		owner: '0x0000000000000000000000000000000000000001', timestampS: 1
	}
}

it('requires nonempty mocked provider extraction through real context mutation', async() => {
	const receipt = mock.method(providers.http, 'assertValidProviderReceipt', async() => ({
		extractedParameters: { account: 'synthetic-commitment' }
	}))
	try {
		const result = await assertValidProviderTranscript(
			[], { clientVersion: 1 } as any, claim() as any,
			logger as any, { version: 1 } as any
		)
		assert.equal(receipt.mock.calls.length, 1)
		const hash = JSON.parse(result.context).providerHash as string
		assertSupportedSignedContext(result.context, assertSupportedInputContext(inputContext(), testAuthIdentity(TEST_CONTEXT_MESSAGE, TEST_CONTEXT_ADDRESS, TEST_SESSION_ID, hash), TEST_CHAIN_IDS))
		assert.deepEqual(JSON.parse(result.context).extractedParameters,
			{ account: 'synthetic-commitment' })
	} finally {
		receipt.mock.restore()
	}

	const emptyReceipt = mock.method(providers.http, 'assertValidProviderReceipt', async() => ({
		extractedParameters: {}
	}))
	try {
		const result = await assertValidProviderTranscript(
			[], { clientVersion: 1 } as any, claim() as any,
			logger as any, { version: 1 } as any
		)
		assert.equal(emptyReceipt.mock.calls.length, 1)
		assert.equal(Object.hasOwn(JSON.parse(result.context), 'extractedParameters'), false)
		assert.throws(() => assertSupportedSignedContext(
			result.context, assertSupportedInputContext(inputContext(), testAuthIdentity(), TEST_CHAIN_IDS)
		), /Unsupported claim context/)
	} finally {
		emptyReceipt.mock.restore()
	}
})
