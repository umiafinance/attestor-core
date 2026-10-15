import assert from 'node:assert/strict'
import { it, mock } from 'node:test'

import type { makeTcpTunnel } from '#src/server/tunnels/make-tcp-tunnel.ts'
import { ClaimTunnelRequest, ClaimTunnelResponse, CreateTunnelRequest, ServiceSignatureType } from '#src/proto/api.ts'
import type { ProviderClaimInfo } from '#src/proto/api.ts'
import { canonicalStringify, createSignDataForClaim } from '#src/utils/claims.ts'
import { SIGNATURES } from '#src/utils/signatures/index.ts'
import { assertSupportedInputContext, assertSupportedSignedContext } from '#src/server/utils/claim-context-policy.ts'
import { inputContext, signedContext, TEST_AUCTION_ADDRESS, TEST_CHAIN_IDS, TEST_CONTEXT_ADDRESS, TEST_CONTEXT_MESSAGE, TEST_IDENTITY_PROVIDER, TEST_PROVIDER_HASH, TEST_SESSION_ID, testAuthIdentity } from '#src/tests/utils/claim-context.ts'

process.env.CLAIM_EPOCH = '2'

process.env.CLAIM_CHAIN_IDS = '10143'
process.env.PRIVATE_KEY = '0x0000000000000000000000000000000000000000000000000000000000000001'

let dialCount = 0
mock.module('#src/server/tunnels/make-tcp-tunnel.ts', {
	namedExports: {
		async makeTcpTunnel(opts: Parameters<typeof makeTcpTunnel>[0]) {
			dialCount++
			return { createRequest: opts, transcript: [], async close() {} }
		}
	}
})

let validatedClaim: ProviderClaimInfo = {
	provider: 'http', parameters: JSON.stringify({ url: 'https://api.example.com/path' }),
	context: signedContext(), owner: '0x0000000000000000000000000000000000000001',
	timestampS: Math.floor(Date.now() / 1000)
}
mock.module('#src/server/utils/assert-valid-claim-request.ts', {
	namedExports: {
		assertTranscriptsMatch() {},
		async assertValidClaimRequest() { return { ...validatedClaim } },
		async assertValidProviderTranscript() { return { ...validatedClaim } }
	}
})

const [{ createTunnel }, { claimTunnel }, { claimTeeBundle }, policy] = await Promise.all([
	import('#src/server/handlers/createTunnel.ts'),
	import('#src/server/handlers/claimTunnel.ts'),
	import('#src/server/handlers/claimTeeBundle.ts'),
	import('#src/server/utils/host-policy.ts')
])
const logger = { info() {}, debug() {}, warn() {}, error() {} }
const whitelist = Object.freeze(['api.example.com', 'xn--bcher-kva.example'])

function client(hosts: readonly string[] = whitelist) {
	return {
		tunnels: {}, isOpen: true, authHostWhitelist: hosts, authIdentity: testAuthIdentity(),
		assertAuthActive() {}, async sendMessage() {},
		metadata: { signatureType: ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH },
		getTunnel() {
			return {
				createRequest: { host: 'api.example.com', port: 443, geoLocation: '', proxySessionId: '' },
				transcript: [], async close() {}
			}
		},
		removeTunnel() {}
	}
}

it('admits only canonical exact sorted signed DNS names', () => {
	for(const host of ['api.example.com', 'xn--bcher-kva.example']) {
		assert.equal(policy.isCanonicalAuthHostname(host), true)
	}
	for(const host of [
		'API.example.com', 'bücher.example', '*.example.com', '.example.com',
		'api..example.com', 'api.example.com.', 'api_example.com',
		'localhost', 'foo.localhost', 'foo.local', 'foo.internal',
		'127.0.0.1', '0127.0.0.1', '[::1]', 'api.example.com:443',
		'a'.repeat(64) + '.example.com'
	]) assert.equal(policy.isCanonicalAuthHostname(host), false, host)
	policy.assertCanonicalHostWhitelist(whitelist)
	for(const list of [[], ['api.example.com', 'api.example.com'],
		['xn--bcher-kva.example', 'api.example.com'], ['*.example.com'],
		['API.example.com'], ['127.0.0.1']]) {
		assert.throws(() => policy.assertCanonicalHostWhitelist(list))
	}
})

it('rejects empty, malformed, unlisted, and non-443 tunnel requests before dialing', async() => {
	const bad = [
		{ hosts: [], host: 'api.example.com', port: 443 },
		{ hosts: ['*.example.com'], host: 'api.example.com', port: 443 },
		{ hosts: whitelist, host: 'other.example.com', port: 443 },
		{ hosts: whitelist, host: 'api.example.com', port: 8443 },
		{ hosts: whitelist, host: 'api.example.com', port: 80, geoLocation: 'US' },
		{ hosts: whitelist, host: 'api.example.com', port: 8443, proxySessionId: 'session123' }
	]
	for(const [index, request] of bad.entries()) {
		dialCount = 0
		await assert.rejects(createTunnel(CreateTunnelRequest.create({ id: index + 1, ...request }),
			{ client: client(request.hosts), logger } as any))
		assert.equal(dialCount, 0)
	}
	dialCount = 0
	await createTunnel(CreateTunnelRequest.create({ id: 99, host: 'api.example.com', port: 443 }),
		{ client: client(), logger } as any)
	assert.equal(dialCount, 1)
})

it('binds signed HTTPS authority to recorded tunnel host and port before both signatures', async() => {
	const ctx = { client: client(), logger } as any
	const req = ClaimTunnelRequest.create({
		request: { id: 1, host: 'api.example.com', port: 443 },
		data: { timestampS: validatedClaim.timestampS, context: inputContext() }
	})
	const verify = SIGNATURES[ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH].verify
	for(const url of ['https://api.example.com/path', 'https://api.example.com:443/path']) {
		const parameters = canonicalStringify({ url, method: 'GET',
			responseMatches: [{ type: 'contains', value: 'ok' }], responseRedactions: [] })
		validatedClaim = { ...validatedClaim, parameters }
		const result = await claimTunnel(req, ctx)
		assert.ok(result.claim && result.signatures)
		assert.equal(result.claim.context, signedContext())
		for(const key of ['contextAddress', 'contextMessage', 'providerHash']) {
			const target = `"${key}":"`
			const start = result.claim.context.indexOf(target) + target.length
			assert.equal(result.claim.context.indexOf(target), result.claim.context.lastIndexOf(target))
			assert.equal(result.claim.context.slice(start, result.claim.context.indexOf('"', start)), JSON.parse(result.claim.context)[key])
		}
		assert.ok(result.claim.context.includes('"extractedParameters":{"account":"synthetic-commitment"}'))
		assert.equal(result.claim.epoch, 2)
		const { claimSignature, resultSignature, attestorAddress } = result.signatures
		assert.equal(await verify(new TextEncoder().encode(createSignDataForClaim(result.claim)), claimSignature, attestorAddress), true)
		assert.equal(await verify(ClaimTunnelResponse.encode({ ...result, signatures: undefined }).finish(), resultSignature, attestorAddress), true)
	}
	for(const url of [
		'https://other.example.com/path', 'https://api.example.com:8443/path',
		'http://api.example.com/path', 'https://API.example.com/path',
		'https://user@api.example.com/path', 'https://api.example.com/path#fragment'
	]) {
		validatedClaim = { ...validatedClaim, parameters: JSON.stringify({ url }) }
		const sign = mock.method(SIGNATURES[ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH], 'sign')
		try {
			await assert.rejects(claimTunnel(req, ctx), /Authenticated claim/)
			assert.equal(sign.mock.calls.length, 0)
		} finally {
			sign.mock.restore()
		}
	}
	for(const parameters of [
		'{"url":"https://evil.example/","url":"https://api.example.com/"}',
		'{"url":"https://api.example.com/","url":"https://evil.example/"}'
	]) {
		validatedClaim = { ...validatedClaim, parameters }
		const sign = mock.method(SIGNATURES[ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH], 'sign')
		try {
			await assert.rejects(claimTunnel(req, ctx), /Authenticated claim/)
			assert.equal(sign.mock.calls.length, 0)
		} finally {
			sign.mock.restore()
		}
	}
	for(const update of [
		{ provider: 'http', parameters: '{}' },
		{ provider: 'dns', parameters: JSON.stringify({ url: 'https://api.example.com/' }) }
	]) {
		validatedClaim = { ...validatedClaim, ...update }
		const sign = mock.method(SIGNATURES[ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH], 'sign')
		try {
			await assert.rejects(claimTunnel(req, ctx), /Authenticated claim/)
			assert.equal(sign.mock.calls.length, 0)
		} finally {
			sign.mock.restore()
		}
	}
})

it('rejects ambiguous or unsupported context before claim and result signatures', async() => {
	validatedClaim = {
		...validatedClaim,
		provider: 'http', parameters: JSON.stringify({ url: 'https://api.example.com/path' }),
		context: signedContext()
	}
	const context = { client: client(), logger } as any
	const request = (raw: string) => ClaimTunnelRequest.create({
		request: { id: 1, host: 'api.example.com', port: 443 },
		data: { timestampS: validatedClaim.timestampS, context: raw }
	})
	const rejectedInput = [
		'{}',
		JSON.stringify({ contextAddress: TEST_CONTEXT_ADDRESS, contextMessage: TEST_CONTEXT_MESSAGE,
			reclaimSessionId: TEST_SESSION_ID, extra: 'client-field' }),
		JSON.stringify({ aa: { contextAddress: TEST_CONTEXT_ADDRESS, extractedParameters: { account: 'decoy' } },
			contextAddress: TEST_CONTEXT_ADDRESS, contextMessage: TEST_CONTEXT_MESSAGE,
			reclaimSessionId: TEST_SESSION_ID }),
		inputContext('different-session'),
		inputContext().replace(TEST_CONTEXT_ADDRESS, '0xABCDEF0000000000000000000000000000000000'),
		inputContext().replace(TEST_CONTEXT_MESSAGE, 'Auction verification'),
		inputContext().replace(TEST_CONTEXT_MESSAGE, `${TEST_CONTEXT_MESSAGE}\\escape`),
		inputContext().replace('"reclaimSessionId":', '"contextAddress":"0x0000000000000000000000000000000000000000","reclaimSessionId":'),
		JSON.stringify({ contextAddress: TEST_CONTEXT_ADDRESS, contextMessage: TEST_CONTEXT_MESSAGE,
			reclaimSessionId: TEST_SESSION_ID, attestationNonce: 'unsupported' }),
		JSON.stringify({ contextAddress: TEST_CONTEXT_ADDRESS, contextMessage: TEST_CONTEXT_MESSAGE,
			extractedParameters: { account: 'client-forged' }, reclaimSessionId: TEST_SESSION_ID }),
		JSON.stringify({ contextAddress: TEST_CONTEXT_ADDRESS, contextMessage: TEST_CONTEXT_MESSAGE,
			providerHash: TEST_PROVIDER_HASH, reclaimSessionId: TEST_SESSION_ID })
	]
	for(const raw of rejectedInput) {
		const sign = mock.method(SIGNATURES[ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH], 'sign')
		try {
			await assert.rejects(claimTunnel(request(raw), context), /Unsupported claim context/)
			assert.equal(sign.mock.calls.length, 0)
		} finally {
			sign.mock.restore()
		}
	}

	const validInput = request(inputContext())
	const parsed = JSON.parse(signedContext())
	const rejectedSigned = [
		'{}',
		JSON.stringify({ contextAddress: TEST_CONTEXT_ADDRESS, contextMessage: TEST_CONTEXT_MESSAGE,
			providerHash: TEST_PROVIDER_HASH, reclaimSessionId: TEST_SESSION_ID }),
		JSON.stringify({ ...parsed, extractedParameters: {} }),
		JSON.stringify({ ...parsed, extractedParameters: { account: '' } }),
		JSON.stringify({ ...parsed, extractedParameters: { account: ' ' } }),
		JSON.stringify({ ...parsed, extractedParameters: { account: { nested: 'decoy' } } }),
		JSON.stringify({ ...parsed, extractedParameters: { contextAddress: 'decoy' } }),
		JSON.stringify({ ...parsed, extractedParameters: { attestationNonce: 'decoy' } }),
		JSON.stringify({ ...parsed, providerHash: TEST_PROVIDER_HASH.toUpperCase() }),
		JSON.stringify({ ...parsed, aa: { contextAddress: TEST_CONTEXT_ADDRESS,
			extractedParameters: { account: 'decoy' } } })
	]
	for(const raw of rejectedSigned) {
		validatedClaim = { ...validatedClaim, context: raw }
		const sign = mock.method(SIGNATURES[ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH], 'sign')
		try {
			await assert.rejects(claimTunnel(validInput, context), /Unsupported claim context/)
			assert.equal(sign.mock.calls.length, 0)
		} finally {
			sign.mock.restore()
		}
	}
	validatedClaim = { ...validatedClaim, context: signedContext() }
})

it('accepts the hook-supported canonical bid context with one raw target each', () => {
	const message = `bid:10143:${TEST_AUCTION_ADDRESS}:1:100:nonce`
	const input = JSON.stringify({
		contextAddress: TEST_CONTEXT_ADDRESS, contextMessage: message,
		identityProvider: TEST_IDENTITY_PROVIDER,
		reclaimSessionId: TEST_SESSION_ID
	})
	const signed = JSON.stringify({
		contextAddress: TEST_CONTEXT_ADDRESS, contextMessage: message,
		extractedParameters: { account: 'synthetic-commitment' },
		identityProvider: TEST_IDENTITY_PROVIDER,
		providerHash: TEST_PROVIDER_HASH, reclaimSessionId: TEST_SESSION_ID
	})
	assertSupportedSignedContext(signed, assertSupportedInputContext(input, testAuthIdentity(message), TEST_CHAIN_IDS))
})

it('rejects TEE before verification, either signature, or a useful response', async() => {
	const sign = mock.method(SIGNATURES[ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH], 'sign')
	try {
		await assert.rejects(claimTeeBundle({} as any, { client: client(), logger } as any),
			(err: any) => err.code === 'ERROR_BAD_REQUEST' && /verified endpoint binding/.test(err.message))
		assert.equal(sign.mock.calls.length, 0)
	} finally {
		sign.mock.restore()
	}
})
