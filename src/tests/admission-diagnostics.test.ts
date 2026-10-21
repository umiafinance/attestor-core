import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { after, describe, it, mock } from 'node:test'
import { Wallet } from 'ethers'

import { CERTIFICATE_TRUST_REASONS } from '#src/tests/utils/certificate-trust-reasons.ts'
import { inputContext, signedContext, TEST_CHAIN_IDS, TEST_CONTEXT_ADDRESS, TEST_IDENTITY_PROVIDER, TEST_SESSION_ID, testAuthIdentity } from '#src/tests/utils/claim-context.ts'
import { SEC_HARDENING_REASONS } from '#src/tests/utils/sec-hardening-reasons.ts'

process.env.CLAIM_EPOCH = '2'
process.env.CLAIM_CHAIN_IDS = '10143'
process.env.PRIVATE_KEY = '0x0000000000000000000000000000000000000000000000000000000000000001'
process.env.HTTPS_PROXY_URL = ''

let handshake: () => unknown = () => {
	throw new Error('synthetic handshake failure')
}
mock.module('#src/server/utils/process-handshake.ts', {
	namedExports: { async processHandshake() { return handshake() } }
})

const [
	{ parseClaimChainIds },
	{ REJECTION_REASONS, rejectionReason },
	{ AttestorError },
	{ redact },
	{ assertValidAuthRequest, createAuthRequest },
	{ authExpiredError },
	{ assertAuthenticatedClaimAuthority, assertAuthenticatedTunnelHost, assertCanonicalHostWhitelist },
	{ assertSupportedInputContext, assertSupportedSignedContext },
	{ assertValidClaimRequest },
	{ makeTcpTunnel },
	{ AttestorServerSocket },
	{ createTunnel },
	{ claimTunnel },
	{ claimTeeBundle },
	{ SIGNATURES },
	proto
] = await Promise.all([
	import('#src/config/claim-chain-ids.ts'),
	import('#src/utils/rejection-reason.ts'),
	import('#src/utils/error.ts'),
	import('#src/utils/logger.ts'),
	import('#src/utils/auth.ts'),
	import('#src/server/utils/auth-session.ts'),
	import('#src/server/utils/host-policy.ts'),
	import('#src/server/utils/claim-context-policy.ts'),
	import('#src/server/utils/assert-valid-claim-request.ts'),
	import('#src/server/tunnels/make-tcp-tunnel.ts'),
	import('#src/server/socket.ts'),
	import('#src/server/handlers/createTunnel.ts'),
	import('#src/server/handlers/claimTunnel.ts'),
	import('#src/server/handlers/claimTeeBundle.ts'),
	import('#src/utils/signatures/index.ts'),
	import('#src/proto/api.ts')
])

type Reason = keyof typeof REJECTION_REASONS
const ETH = proto.ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH
const logger = { info() {}, debug() {}, warn() {}, error() {}, trace() {}, child() { return logger } } as any
const exercised = new Set<Reason>()

async function expectReason(reason: Reason, code: string, action: () => unknown) {
	await assert.rejects(async() => action(), (err: unknown) => {
		assert.ok(err instanceof AttestorError, String(err))
		assert.equal(err.code, code)
		assert.equal(rejectionReason(err), reason)
		assert.deepEqual(JSON.parse(err.toProto().data), { ...err.data, reason })
		return true
	})
	exercised.add(reason)
}

function authData(overrides: Partial<{ id: string, expiresAt: number, hostWhitelist: string[] }> = {}) {
	const now = Math.floor(Date.now() / 1000)
	return { id: TEST_SESSION_ID, createdAt: now, expiresAt: now + 60, hostWhitelist: ['example.com'], ...overrides }
}

function tunnel(createRequest: Record<string, unknown> = {}, transcript: unknown[] = []) {
	return { createRequest: { host: 'example.com', port: 443, geoLocation: '', proxySessionId: '', ...createRequest }, transcript, async close() {} }
}

function claimClient(overrides: Record<string, unknown> = {}) {
	return {
		authIdentity: testAuthIdentity(),
		authHostWhitelist: ['example.com'],
		metadata: { signatureType: ETH, clientVersion: proto.AttestorVersion.ATTESTOR_VERSION_3_2_0 },
		tunnels: {},
		assertAuthActive() {},
		getTunnel() { return tunnel() },
		removeTunnel() {},
		...overrides
	}
}

function claimRequest(context = inputContext(), timestampS = Math.floor(Date.now() / 1000), transcript: any[] = []) {
	return proto.ClaimTunnelRequest.create({
		request: { id: 1, host: 'example.com', port: 443 },
		data: { provider: 'http', parameters: '{"url":"https://example.com/"}', context, timestampS },
		transcript
	})
}

const VALID_HTTP_PARAMS = '{"method":"GET","responseMatches":[{"type":"contains","value":"synthetic"}],"url":"https://example.com/"}'

async function signedClaimRequest(owner: { address: string, privateKey: string }, parameters = VALID_HTTP_PARAMS) {
	const request = proto.ClaimTunnelRequest.create({
		request: { id: 1, host: 'example.com', port: 443 },
		data: { provider: 'http', parameters, context: inputContext(), owner: owner.address.toLowerCase(), timestampS: Math.floor(Date.now() / 1000) }
	})
	const signature = await SIGNATURES[ETH].sign(proto.ClaimTunnelRequest.encode(request).finish(), owner.privateKey)
	return { ...request, signatures: { requestSignature: signature } }
}

describe('CLAIM_CHAIN_IDS', () => {
	it('accepts only strictly ascending canonical decimal chain IDs', () => {
		assert.deepEqual(parseClaimChainIds('10143'), ['10143'])
		assert.deepEqual(parseClaimChainIds('1,8453,10143'), ['1', '8453', '10143'])
		assert.deepEqual(parseClaimChainIds('9007199254740991'), ['9007199254740991'])
		for(const raw of [undefined, '', '0', '010143', '+10143', '-1', '1.0', '1e4', '0x279f', ' 10143', '10143 ',
			'10143,', ',10143', '10143,,1', '10143,1', '1,1', '1, 2', '9007199254740992']) {
			assert.throws(() => parseClaimChainIds(raw), /CLAIM_CHAIN_IDS/, String(raw))
		}
	})

	it('fails before the server listener when missing or malformed', () => {
		for(const raw of [undefined, '', '10143,10143']) {
			const env: NodeJS.ProcessEnv = { ...process.env, CLAIM_EPOCH: '2' }
			if(raw === undefined) delete env.CLAIM_CHAIN_IDS
			else env.CLAIM_CHAIN_IDS = raw
			const result = spawnSync(process.execPath, ['--experimental-strip-types', 'src/scripts/start-server.ts'], { env, encoding: 'utf8', timeout: 10_000 })
			assert.notEqual(result.status, 0)
			assert.match(result.stderr, /CLAIM_CHAIN_IDS must be strictly ascending/)
		}
	})

	it('admits register, bid and sandbox forms only on configured chains', () => {
		const forms = [
			`register:%c:0x${'4'.repeat(40)}:nonce`,
			`bid:%c:0x${'4'.repeat(40)}:0:1:nonce`,
			`sandbox:%c:${TEST_CONTEXT_ADDRESS}:3f2b6c1e-8d4a-4b7c-9e2f-1a2b3c4d5e6f`
		]
		for(const form of forms) {
			const message = (chain: string) => form.replace('%c', chain)
			const raw = (chain: string) => JSON.stringify({ contextAddress: TEST_CONTEXT_ADDRESS, contextMessage: message(chain), identityProvider: TEST_IDENTITY_PROVIDER, reclaimSessionId: TEST_SESSION_ID })
			assert.equal(assertSupportedInputContext(raw('84532'), testAuthIdentity(message('84532')), ['84532', '10143']).reclaimSessionId, TEST_SESSION_ID)
			assert.throws(() => assertSupportedInputContext(raw('84532'), testAuthIdentity(message('84532')), TEST_CHAIN_IDS), (err: unknown) => rejectionReason(err) === 'CLAIM_CONTEXT_CHAIN_NOT_ALLOWED')
			assert.throws(() => assertSupportedInputContext(raw('010143'), testAuthIdentity(message('010143')), TEST_CHAIN_IDS), (err: unknown) => rejectionReason(err) === 'CLAIM_CONTEXT_MESSAGE_UNSUPPORTED')
		}
	})
})

describe('finite rejection reasons', () => {
	after(() => {
		const reasons = Object.keys(REJECTION_REASONS).filter(reason => !SEC_HARDENING_REASONS.includes(reason) && !CERTIFICATE_TRUST_REASONS.includes(reason))
		assert.deepEqual([...exercised].sort(), reasons.sort(), 'a reason in the table has no test')
	})

	it('labels auth failures', async() => {
		const issuer = Wallet.createRandom()
		process.env.AUTHENTICATION_PUBLIC_KEY = issuer.publicKey
		try {
			await expectReason('AUTH_REQUIRED', 'ERROR_AUTHENTICATION_FAILED', () => assertValidAuthRequest(undefined, ETH))
			await expectReason('AUTH_INVALID', 'ERROR_AUTHENTICATION_FAILED', () => assertValidAuthRequest({ signature: new Uint8Array() } as any, ETH))
			const foreign = await createAuthRequest(authData(), Wallet.createRandom().privateKey)
			await expectReason('AUTH_INVALID', 'ERROR_AUTHENTICATION_FAILED', () => assertValidAuthRequest(foreign, ETH))
			const expired = await createAuthRequest(authData({ expiresAt: Math.floor(Date.now() / 1000) }), issuer.privateKey)
			await expectReason('AUTH_EXPIRED', 'ERROR_AUTHENTICATION_FAILED', () => assertValidAuthRequest(expired, ETH))
		} finally {
			delete process.env.AUTHENTICATION_PUBLIC_KEY
		}
		await expectReason('AUTH_EXPIRED', 'ERROR_AUTHENTICATION_FAILED', () => { throw authExpiredError() })
		await expectReason('HOST_LIST_INVALID', 'ERROR_BAD_REQUEST', () => assertCanonicalHostWhitelist([]))
		await expectReason('HOST_LIST_INVALID', 'ERROR_BAD_REQUEST', () => assertCanonicalHostWhitelist(['b.example.com', 'a.example.com']))
	})

	it('labels tunnel admission failures', async() => {
		const ctx = (client: Record<string, unknown>) => ({ logger, client }) as any
		await expectReason('AUTH_REQUIRED', 'ERROR_AUTHENTICATION_FAILED', () => createTunnel({ id: 1, host: 'example.com', port: 443 } as any, ctx(claimClient({ authHostWhitelist: undefined }))))
		await expectReason('TUNNEL_ID_IN_USE', 'ERROR_BAD_REQUEST', () => createTunnel({ id: 1, host: 'example.com', port: 443 } as any, ctx(claimClient({ tunnels: { 1: tunnel() } }))))
		await expectReason('PORT_NOT_ALLOWED', 'ERROR_BAD_REQUEST', () => createTunnel({ id: 1, host: 'example.com', port: 8443 } as any, ctx(claimClient())))
		await expectReason('HOST_NOT_ALLOWED', 'ERROR_BAD_REQUEST', () => createTunnel({ id: 1, host: 'other.example', port: 443 } as any, ctx(claimClient())))
		await expectReason('HOST_NOT_ALLOWED', 'ERROR_BAD_REQUEST', () => assertAuthenticatedTunnelHost(['example.com'], 'sub.example.com', 443))
		await expectReason('PROXY_NOT_CONFIGURED', 'ERROR_BAD_REQUEST', () => makeTcpTunnel({ host: 'example.com', port: 443, geoLocation: 'US', logger } as any))
		await expectReason('TUNNEL_NOT_FOUND', 'ERROR_NOT_FOUND', () => AttestorServerSocket.prototype.getTunnel.call({ tunnels: {} } as any, 9))
	})

	it('labels claimTunnel rejections before validation and signing', async() => {
		const ctx = (client: Record<string, unknown>) => ({ logger, client }) as any
		await expectReason('TUNNEL_REQUEST_MISMATCH', 'ERROR_BAD_REQUEST', () => claimTunnel(claimRequest(), ctx(claimClient({ getTunnel: () => tunnel({ port: 8443 }) }))))
		const tunnelBytes = [{ sender: 'client', message: new Uint8Array([1]) }]
		const claimBytes = [{ sender: proto.TranscriptMessageSenderType.TRANSCRIPT_MESSAGE_SENDER_TYPE_CLIENT, message: new Uint8Array([2]) }]
		await expectReason('TRANSCRIPT_MISMATCH', 'ERROR_BAD_REQUEST', () => claimTunnel(claimRequest(inputContext(), undefined, claimBytes), ctx(claimClient({ getTunnel: () => tunnel({}, tunnelBytes) }))))
		await expectReason('CLAIM_CONTEXT_INVALID', 'ERROR_BAD_REQUEST', () => claimTunnel(claimRequest('{"contextAddress":"0x1"}'), ctx(claimClient())))
		await expectReason('CLAIM_CONTEXT_SESSION_MISMATCH', 'ERROR_BAD_REQUEST', () => claimTunnel(claimRequest(inputContext('another-session')), ctx(claimClient())))
		const otherChain = inputContext().replace(':10143:', ':84532:')
		await expectReason('CLAIM_CONTEXT_CHAIN_NOT_ALLOWED', 'ERROR_BAD_REQUEST', () => claimTunnel(claimRequest(otherChain), ctx(claimClient())))
		const freeText = JSON.stringify({ contextAddress: TEST_CONTEXT_ADDRESS, contextMessage: 'Auction verification', identityProvider: TEST_IDENTITY_PROVIDER, reclaimSessionId: TEST_SESSION_ID })
		await expectReason('CLAIM_CONTEXT_MESSAGE_UNSUPPORTED', 'ERROR_BAD_REQUEST', () => assertSupportedInputContext(freeText, testAuthIdentity('Auction verification'), TEST_CHAIN_IDS))
		const accepted = assertSupportedInputContext(inputContext(), testAuthIdentity(), TEST_CHAIN_IDS)
		await expectReason('SIGNED_CONTEXT_INVALID', 'ERROR_BAD_REQUEST', () => assertSupportedSignedContext(signedContext('synthetic', 'another-session'), accepted))
		await expectReason('AUTH_EXPIRED', 'ERROR_AUTHENTICATION_FAILED', () => claimTunnel(claimRequest(), ctx(claimClient({ assertAuthActive() { throw authExpiredError() } }))))
		await expectReason('TEE_CLAIMS_DISABLED', 'ERROR_BAD_REQUEST', () => claimTeeBundle({} as any, ctx(claimClient())))

		const skewed = await claimTunnel(claimRequest(inputContext(), Math.floor(Date.now() / 1000) + 3600), ctx(claimClient()))
		const skewError = AttestorError.fromProto(skewed.error)
		assert.equal(skewError.code, 'ERROR_INVALID_CLAIM')
		await expectReason('CLAIM_TIMESTAMP_SKEW', 'ERROR_INVALID_CLAIM', () => { throw skewError })
	})

	it('labels claim authority failures before signing', async() => {
		const claim = (provider: string, parameters: string) => ({ provider, parameters, context: '', owner: '', timestampS: 0, epoch: 2, identifier: '' }) as any
		await expectReason('TUNNEL_REQUEST_MISMATCH', 'ERROR_BAD_REQUEST', () => assertAuthenticatedClaimAuthority(claim('http', '{"url":"https://example.com/"}'), ['example.com'], undefined, undefined))
		await expectReason('CLAIM_PROVIDER_UNSUPPORTED', 'ERROR_BAD_REQUEST', () => assertAuthenticatedClaimAuthority(claim('tee', '{"url":"https://example.com/"}'), ['example.com'], 'example.com', 443))
		await expectReason('CLAIM_PARAMS_INVALID', 'ERROR_BAD_REQUEST', () => assertAuthenticatedClaimAuthority(claim('http', '{ "url":"https://example.com/"}'), ['example.com'], 'example.com', 443))
		await expectReason('CLAIM_URL_MISMATCH', 'ERROR_BAD_REQUEST', () => assertAuthenticatedClaimAuthority(claim('http', '{"url":"https://evil.example/"}'), ['example.com'], 'example.com', 443))
	})

	it('labels each claim validation stage', async() => {
		await expectReason('CLAIM_REQUEST_INVALID', 'ERROR_INVALID_CLAIM', () => assertValidClaimRequest(proto.ClaimTunnelRequest.create({}), { signatureType: ETH } as any, logger))
		const owner = Wallet.createRandom()
		const signed = await signedClaimRequest(owner)
		const metadata = { signatureType: ETH, clientVersion: proto.AttestorVersion.ATTESTOR_VERSION_3_2_0 } as any
		await expectReason('CLAIM_SIGNATURE_INVALID', 'ERROR_INVALID_CLAIM', () => assertValidClaimRequest({ ...signed, signatures: undefined }, metadata, logger))
		const forged = { ...signed, data: { ...signed.data!, owner: Wallet.createRandom().address.toLowerCase() } }
		await expectReason('CLAIM_SIGNATURE_INVALID', 'ERROR_INVALID_CLAIM', () => assertValidClaimRequest(forged, metadata, logger))
		await expectReason('TRANSCRIPT_DECRYPT_FAILED', 'ERROR_INVALID_CLAIM', () => assertValidClaimRequest(signed, metadata, logger))
		handshake = () => ({ tlsVersion: 'TLS1_3', cipherSuite: 'TLS_CHACHA20_POLY1305_SHA256', hostname: 'other.example', nextMsgIndex: 0 })
		await expectReason('TLS_HOST_MISMATCH', 'ERROR_INVALID_CLAIM', () => assertValidClaimRequest(signed, metadata, logger))
		handshake = () => ({ tlsVersion: 'TLS1_3', cipherSuite: 'TLS_CHACHA20_POLY1305_SHA256', hostname: 'example.com', nextMsgIndex: 0 })
		const schemaInvalid = await signedClaimRequest(owner, '{"url":"https://example.com/"}')
		await expectReason('PROVIDER_PARAMS_INVALID', 'ERROR_BAD_REQUEST', () => assertValidClaimRequest(schemaInvalid, metadata, logger))
		await expectReason('PROVIDER_VALIDATION_FAILED', 'ERROR_INVALID_CLAIM', () => assertValidClaimRequest(signed, metadata, logger))
	})

	it('projects only known reasons into logs', () => {
		const known = new AttestorError('ERROR_BAD_REQUEST', 'CANARY_MESSAGE', { reason: 'HOST_NOT_ALLOWED', host: 'CANARY_HOST' })
		assert.deepEqual(redact({ err: known }), { errorCode: 'ERROR_BAD_REQUEST', reason: 'HOST_NOT_ALLOWED' })
		const unknown = new AttestorError('ERROR_BAD_REQUEST', 'CANARY_MESSAGE', { reason: 'CANARY_REASON' })
		assert.deepEqual(redact({ err: unknown }), { errorCode: 'ERROR_BAD_REQUEST' })
		assert.deepEqual(redact({ reason: 'CANARY_REASON', errorCode: 'ERROR_BAD_REQUEST' }), { errorCode: 'ERROR_BAD_REQUEST' })
	})
})
