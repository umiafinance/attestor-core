import { createHash } from 'node:crypto'

export const TEST_SESSION_ID = 'bound-session-id'
export const TEST_CHAIN_IDS: readonly string[] = ['10143']
export const TEST_CONTEXT_ADDRESS = '0x3333333333333333333333333333333333333333'
export const TEST_AUCTION_ADDRESS = '0x4444444444444444444444444444444444444444'
export const TEST_CONTEXT_MESSAGE = `register:10143:${TEST_AUCTION_ADDRESS}:nonce`
export const TEST_PROVIDER_HASH = `0x${'a'.repeat(64)}`
export const TEST_IDENTITY_PROVIDER = 'github'

export function testAuthIdentity(
	contextMessage = TEST_CONTEXT_MESSAGE,
	contextAddress = TEST_CONTEXT_ADDRESS,
	sessionId = TEST_SESSION_ID,
	providerHash = TEST_PROVIDER_HASH
) {
	const messageDigest = `sha256:${createHash('sha256').update(contextMessage).digest('hex')}`
	const scopeDigest = createHash('sha256').update(`${contextAddress}:${messageDigest}`).digest('hex')
	return `umia1:${sessionId}:${TEST_IDENTITY_PROVIDER}:${providerHash}:${scopeDigest}`
}

export function inputContext(sessionId = TEST_SESSION_ID) {
	return JSON.stringify({
		contextAddress: TEST_CONTEXT_ADDRESS,
		contextMessage: TEST_CONTEXT_MESSAGE,
		identityProvider: TEST_IDENTITY_PROVIDER,
		reclaimSessionId: sessionId
	})
}

export function signedContext(account = 'synthetic-commitment', sessionId = TEST_SESSION_ID) {
	return JSON.stringify({
		contextAddress: TEST_CONTEXT_ADDRESS,
		contextMessage: TEST_CONTEXT_MESSAGE,
		extractedParameters: { account },
		identityProvider: TEST_IDENTITY_PROVIDER,
		providerHash: TEST_PROVIDER_HASH,
		reclaimSessionId: sessionId
	})
}
