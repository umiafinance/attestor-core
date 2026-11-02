import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { it, mock } from 'node:test'
import { Wallet } from 'ethers'

import { inputContext, TEST_CONTEXT_ADDRESS, TEST_CONTEXT_MESSAGE, TEST_SESSION_ID, testAuthIdentity } from '#src/tests/utils/claim-context.ts'

process.env.CLAIM_EPOCH = '2'
process.env.CLAIM_CHAIN_IDS = '10143'
process.env.PRIVATE_KEY = '0x0000000000000000000000000000000000000000000000000000000000000001'

// Isolate the authorization boundary from TLS proof verification.
mock.module('#src/server/utils/process-handshake.ts', {
	namedExports: { async processHandshake() {
		return { tlsVersion: 'TLS1_3', cipherSuite: 'TLS_CHACHA20_POLY1305_SHA256', hostname: 'api.example.com', nextMsgIndex: 0 }
	} }
})

const [{ claimTunnel }, { assertValidProviderTranscript }, { providers }, { canonicalStringify, hashProviderParams }, { ClaimTunnelRequest, ServiceSignatureType, AttestorVersion }, { SIGNATURES }] = await Promise.all([
	import('#src/server/handlers/claimTunnel.ts'),
	import('#src/server/utils/assert-valid-claim-request.ts'),
	import('#src/providers/index.ts'),
	import('#src/utils/claims.ts'),
	import('#src/proto/api.ts'),
	import('#src/utils/signatures/index.ts')
])
const logger = { info() {}, debug() {}, warn() {}, error() {}, trace() {} } as any
const params = {
	url: 'https://api.example.com/path', method: 'GET',
	responseMatches: [{ type: 'regex', value: '(?<account>[a-z]+)' }],
	responseRedactions: [{ regex: '(?<account>[a-z]+)' }]
} as const
const hash = hashProviderParams(params as any)
const metadata = { signatureType: ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH, clientVersion: AttestorVersion.ATTESTOR_VERSION_3_2_0 }

it('authorizes session provider parameters before invoking the receipt validator', async() => {
	const owner = Wallet.createRandom()
	const receipt = mock.method(providers.http, 'assertValidProviderReceipt', async() => ({ extractedParameters: { account: 'synthetic' } }))
	const client = {
		metadata, authHostWhitelist: ['api.example.com'],
		authIdentity: testAuthIdentity(TEST_CONTEXT_MESSAGE, TEST_CONTEXT_ADDRESS, TEST_SESSION_ID, hash),
		assertAuthActive() {}, removeTunnel() {},
		getTunnel() { return {
			createRequest: { host: 'api.example.com', port: 443, geoLocation: '', proxySessionId: '' },
			transcript: [], async close() {}
		} }
	}
	try {
		for(const selected of [
			{ ...params, responseMatches: [{ type: 'regex', value: '([a-z]+)+$' }] },
			{ ...params, responseRedactions: [{ regex: '([a-z]+)+$' }] },
			params
		]) {
			const request = ClaimTunnelRequest.create({
				request: { id: 1, host: 'api.example.com', port: 443 },
				data: { provider: 'http', parameters: canonicalStringify(selected), context: inputContext(), owner: owner.address.toLowerCase(), timestampS: Math.floor(Date.now() / 1000) }
			})
			const signature = await SIGNATURES[metadata.signatureType].sign(ClaimTunnelRequest.encode(request).finish(), owner.privateKey)
			request.signatures = { requestSignature: signature }
			const result = await claimTunnel(request, { client, logger } as any)
			if(selected === params) {
				assert.ok(result.claim)
				assert.equal(JSON.parse(result.claim.context).providerHash, hash)
				assert.equal(receipt.mock.calls.length, 1)
			} else {
				assert.equal(result.claim, undefined)
				assert.equal(JSON.parse(result.error!.data).reason, 'PROVIDER_PARAMS_INVALID')
				assert.equal(receipt.mock.calls.length, 0)
			}
		}
	} finally { receipt.mock.restore() }
})

it('authorizes the hash after OPRF replacements and rejects a missing allowlist', async() => {
	const receipt = mock.method(providers.http, 'assertValidProviderReceipt', async() => ({ extractedParameters: { account: 'synthetic' } }))
	const raw = { ...params, responseMatches: [{ type: 'regex', value: 'original' }] }
	const replaced = { ...raw, responseMatches: [{ type: 'regex', value: 'nullifier' }] }
	const info = () => ({ provider: 'http', parameters: canonicalStringify(raw), context: inputContext(), owner: '', timestampS: 0 })
	const replacements = [{ originalText: 'original', nullifierText: 'nullifier' }]
	try {
		await assert.rejects(assertValidProviderTranscript([], metadata as any, info(), logger, { version: metadata.clientVersion }))
		await assert.rejects(assertValidProviderTranscript([], metadata as any, info(), logger, { version: metadata.clientVersion }, replacements, [hashProviderParams(raw as any)]))
		assert.equal(receipt.mock.calls.length, 0)
		const result = await assertValidProviderTranscript([], metadata as any, info(), logger, { version: metadata.clientVersion }, replacements, [hashProviderParams(replaced as any)])
		assert.equal(result.parameters, canonicalStringify(replaced))
		assert.equal(JSON.parse(result.context).providerHash, hashProviderParams(replaced as any))
		assert.equal(receipt.mock.calls.length, 1)
	} finally { receipt.mock.restore() }
})

it('uses RE2 immediately and completes adversarial non-matches within a process deadline', () => {
	const result = spawnSync(process.execPath, ['--experimental-strip-types', '--input-type=module', '-e', `
		import assert from 'node:assert/strict'
		import { makeRegex } from '#src/providers/http/utils.ts'
		assert.equal(makeRegex('test').constructor.name, 'RE2')
		assert.equal(makeRegex('([a-z]+)+$').exec('a'.repeat(100_000) + '!'), null)
		assert.equal(makeRegex('(?<account>[a-z]+)').exec('alice')?.groups?.account, 'alice')
		assert.throws(() => makeRegex('(?=a)a'))
	`], { encoding: 'utf8', timeout: 10_000 })
	assert.equal(result.error, undefined, String(result.error))
	assert.equal(result.status, 0, result.stderr)
})
