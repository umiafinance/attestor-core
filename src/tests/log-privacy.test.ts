import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { Writable } from 'node:stream'
import { setTimeout as delay } from 'node:timers/promises'
import { it, mock } from 'node:test'
import { Wallet } from 'ethers'
import { inputContext, signedContext, TEST_SESSION_ID, testAuthIdentity } from '#src/tests/utils/claim-context.ts'
import { canonicalStringify } from '#src/utils/claims.ts'

process.env.CLAIM_EPOCH = '2'

process.env.CLAIM_CHAIN_IDS = '10143'
process.env.PRIVATE_KEY = '0x0000000000000000000000000000000000000000000000000000000000000001'
process.env.DISABLE_BGP_CHECKS = '1'

const canaries = {
	auth: 'CANARY_AUTH_PRIVATE', requestId: 'CANARY_REQUEST_PRIVATE',
	host: 'CANARY_HOST_PRIVATE', headers: 'CANARY_COOKIE_PRIVATE',
	proof: 'CANARY_PROOF_PRIVATE', account: 'CANARY_ACCOUNT_PRIVATE',
	error: 'CANARY_ERROR_PRIVATE', key: 'CANARY_KEY_PRIVATE'
}
const VERIFIED_SESSION_ID = 'verified-zktls-session'
const claimInfo = {
	provider: 'http', parameters: canonicalStringify({ url: 'https://example.com/', secret: canaries.account }),
	context: signedContext(canaries.proof), owner: canaries.account,
	timestampS: Math.floor(Date.now() / 1000)
}
let failTunnel = false
const nestedError = Object.assign(new Error(canaries.error), {
	cause: { message: canaries.key, headers: { cookie: canaries.headers }, nested: new Error(canaries.proof) }
})

mock.module('#src/server/utils/assert-valid-claim-request.ts', {
	namedExports: {
		assertTranscriptsMatch() {},
		async assertValidClaimRequest() {
			if(failTunnel) throw nestedError
			return { ...claimInfo }
		},
		async assertValidProviderTranscript() {
			return { ...claimInfo }
		}
	}
})
const [loggerModule, { AttestorClient }, { WS_PATHNAME }, { createServer }, { getRandomPort }, { createAuthRequest }, { claimTunnel }, { claimTeeBundle }, proto] = await Promise.all([
	import('#src/utils/logger.ts'),
	import('#src/client/utils/client-socket.ts'),
	import('#src/config/index.ts'),
	import('#src/server/create-server.ts'),
	import('#src/tests/utils.ts'),
	import('#src/utils/auth.ts'),
	import('#src/server/handlers/claimTunnel.ts'),
	import('#src/server/handlers/claimTeeBundle.ts'),
	import('#src/proto/api.ts')
])

function capture(level: 'info' | 'debug' | 'trace') {
	const lines: string[] = []
	const stream = new Writable({ write(chunk, _encoding, done) { lines.push(chunk.toString()); done() } })
	const logger = loggerModule.makeLogger(false, level, undefined, stream)
	return { logger, lines }
}

function assertPrivateLogs(lines: string[]) {
	const raw = lines.join('')
	for(const canary of Object.values(canaries)) assert.ok(!raw.includes(canary), 'synthetic secret reached a log')
	const allowed = new Set(['level', 'time', 'connectionRef', 'operationRef', 'zktlsSessionId', 'handler', 'stage', 'outcome', 'errorCode', 'reason', 'durationMs', 'msg'])
	const records = lines.map(line => { const keys = [...line.matchAll(/"([A-Za-z][A-Za-z0-9]*)":/g)].map(match => match[1]); assert.equal(new Set(keys).size, keys.length, 'duplicate JSON key in log line'); return JSON.parse(line) as Record<string, unknown> })
	for(const record of records) {
		assert.ok(Object.keys(record).every(key => allowed.has(key)))
		assert.equal(record.msg, 'attestor diagnostic')
		if(record.connectionRef) assert.match(String(record.connectionRef), /^[0-9a-f-]{36}$/)
		if(record.operationRef) assert.match(String(record.operationRef), /^[0-9a-f-]{36}$/)
		if(record.zktlsSessionId) assert.equal(record.zktlsSessionId, VERIFIED_SESSION_ID)
	}
	return records
}

for(const level of ['info', 'debug'] as const) {
	it(`keeps ${level} actual init, tunnel, claims, signing and delivery logs categorical`, async() => {
		const { logger, lines } = capture(level)
		const key = Wallet.createRandom()
		process.env.AUTHENTICATION_PUBLIC_KEY = key.publicKey
		const port = getRandomPort()
		const server = await createServer(port)
		const url = `ws://127.0.0.1:${port}${WS_PATHNAME}`
		let client: InstanceType<typeof AttestorClient> | undefined
		try {
			const missing = new AttestorClient({ url })
			await assert.rejects(missing.waitForInit(), (err: any) => err.code === 'ERROR_AUTHENTICATION_FAILED')
			const wrong = await createAuthRequest({ id: canaries.auth, hostWhitelist: [canaries.host] }, Wallet.createRandom().privateKey)
			const invalid = new AttestorClient({ url, authRequest: wrong })
			await assert.rejects(invalid.waitForInit(), (err: any) => err.code === 'ERROR_AUTHENTICATION_FAILED')

			const expiresAt = Math.floor(Date.now() / 1000) + 3
			const auth = await createAuthRequest({ id: VERIFIED_SESSION_ID, hostWhitelist: ['example.com'], expiresAt }, key.privateKey)
			client = new AttestorClient({ url, authRequest: auth })
			await client.waitForInit()
			const ws = [...server.clients].find(socket => (socket as any).serverSocket?.authIdentity === VERIFIED_SESSION_ID)!
			const socket = (ws as any).serverSocket
			const rpc = (type: string, data: unknown) => new Promise<any>(resolve =>
				socket.dispatchRPCEvent('rpc-request', { type, data, requestId: canaries.requestId, respond: resolve }))
			const beforeTunnelFailure = lines.length
			const tunnelError = await rpc('createTunnel', { id: 7, host: canaries.host, port: 443 })
			assert.equal(tunnelError.code, 'ERROR_BAD_REQUEST')
			const tunnelFailures = assertPrivateLogs(lines.slice(beforeTunnelFailure)).filter(item => item.outcome === 'failure')
			assert.equal(tunnelFailures.length, 1, 'createTunnel emitted duplicate failure records')
			assert.ok(tunnelFailures[0].connectionRef && tunnelFailures[0].operationRef, JSON.stringify(tunnelFailures[0]))
			assert.equal(tunnelFailures[0].zktlsSessionId, VERIFIED_SESSION_ID)
			assert.equal(tunnelFailures[0].reason, 'HOST_NOT_ALLOWED')
			for(const [type, data] of [
				['claimTunnel', {}],
				['claimTeeBundle', {}]
			] as const) {
				const before = lines.length
				await rpc(type, data)
				const failures = assertPrivateLogs(lines.slice(before)).filter(item => item.outcome === 'failure')
				assert.equal(failures.length, 1, `${type} emitted duplicate failure records`)
				assert.equal(failures[0].stage, 'rpc')
				assert.ok(failures[0].connectionRef && failures[0].operationRef)
			}

			const request = proto.ClaimTunnelRequest.create({ request: { id: 1, host: 'example.com', port: 443 }, data: { timestampS: claimInfo.timestampS, context: inputContext() } })
			const handlerLogger = logger.child({ connectionRef: loggerModule.createServerLogRef(randomUUID), operationRef: loggerModule.createServerLogRef(randomUUID), handler: 'claimTunnel', userId: canaries.auth, requestId: canaries.requestId })
			const handlerClient = {
				authIdentity: testAuthIdentity(),
				authHostWhitelist: Object.freeze(['example.com']),
				metadata: { signatureType: proto.ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH, clientVersion: proto.AttestorVersion.ATTESTOR_VERSION_3_2_0 },
				assertAuthActive() {},
				getTunnel() { return { createRequest: { host: 'example.com', port: 443, geoLocation: '', proxySessionId: '' }, transcript: [], async close() {} } },
				removeTunnel() {}
			}
			const context = { logger: handlerLogger, client: handlerClient } as any
			const successTunnel = await claimTunnel(request, context)
			assert.ok(successTunnel.signatures?.claimSignature.length)
			failTunnel = true
			const beforeFailedClaim = lines.length
			const failedTunnel = await claimTunnel(request, context)
			assert.equal(failedTunnel.error?.code, proto.ErrorCode.ERROR_INVALID_CLAIM)
			const rejectedRecords = assertPrivateLogs(lines.slice(beforeFailedClaim))
			const claimOutcomes = rejectedRecords.filter(item => item.stage === 'claimTunnel').map(item => item.outcome)
			assert.ok(claimOutcomes.length > 0)
			assert.ok(claimOutcomes.every(outcome => outcome === 'failure'))
			failTunnel = false

			const teeLogger = logger.child({ connectionRef: loggerModule.createServerLogRef(randomUUID), operationRef: loggerModule.createServerLogRef(randomUUID), handler: 'claimTeeBundle' })
			const teeContext = { logger: teeLogger, client: handlerClient } as any
			const teeRequest = proto.ClaimTeeBundleRequest.create({ verificationBundle: new Uint8Array(), data: { ...claimInfo } })
			await assert.rejects(claimTeeBundle(teeRequest, teeContext), /verified endpoint binding/)

			logger.child({ userId: canaries.auth, hostname: canaries.host, requestId: canaries.requestId }).error({
				err: nestedError, headers: { cookie: canaries.headers }, privateKey: canaries.key,
				proof: canaries.proof, claim: claimInfo
			}, `untrusted ${canaries.error}`)
			logger.error(nestedError, canaries.error)
			while(Date.now() <= expiresAt * 1000 + 100) await delay(25)
			const records = assertPrivateLogs(lines)
			const initFailures = records.filter(item => item.stage === 'init' && item.outcome === 'failure')
			assert.ok(initFailures.some(item => item.errorCode === 'ERROR_AUTHENTICATION_FAILED' && item.reason === 'AUTH_REQUIRED'))
			assert.ok(initFailures.some(item => item.errorCode === 'ERROR_AUTHENTICATION_FAILED' && item.reason === 'AUTH_INVALID'))
			assert.ok(initFailures.every(item => item.zktlsSessionId === undefined), 'unverified auth ID reached a log')
			assert.ok(records.some(item => item.stage === 'init' && item.outcome === 'success' && item.zktlsSessionId === VERIFIED_SESSION_ID))
			assert.ok(records.some(item => item.stage === 'init' && item.outcome === 'expired' && item.zktlsSessionId === VERIFIED_SESSION_ID))
			assert.ok(records.some(item => item.stage === 'rpc' && item.outcome === 'failure' && item.errorCode === 'ERROR_BAD_REQUEST'))
			for(const stage of ['claimTunnel']) {
				assert.ok(records.some(item => item.stage === stage && item.outcome === 'success'))
				assert.ok(records.some(item => item.stage === stage && item.outcome === 'failure'))
			}
			assert.ok(records.some(item => item.stage === 'rpc' && typeof item.durationMs === 'number'))
			assert.ok(records.some(item => item.stage === 'rpc' && item.outcome === 'failure' && item.errorCode === 'INTERNAL_ERROR'))
			assert.ok(records.filter(item => item.outcome === 'started' || item.outcome === 'success').every(item => item.errorCode === undefined))
			assert.ok(records.some(item => item.connectionRef && item.operationRef))
		} finally {
			failTunnel = false
			await client?.terminateConnection()
			await new Promise<void>(resolve => server.close(() => resolve()))
			delete process.env.AUTHENTICATION_PUBLIC_KEY
			loggerModule.makeLogger(false, 'info')
		}
	})
}

it('sanitizes outgoing trace and throwing log values without changing the caller result', () => {
	const { logger, lines } = capture('trace')
	const forgedRef = randomUUID()
	const missingRef = loggerModule.createServerLogRef(() => { throw nestedError })
	assert.equal(missingRef, undefined)
	assert.equal(loggerModule.createServerLogRef(() => canaries.auth), undefined)
	logger.child({ connectionRef: missingRef }).warn('auth expired')
	const child = logger.child({ connectionRef: forgedRef, authId: canaries.auth, zktlsSessionId: canaries.auth, reason: canaries.error })
	logger.child({ connectionRef: loggerModule.createServerLogRef(randomUUID) }).child({ handler: 'claimTunnel' }).trace({ msg: { headers: { cookie: canaries.headers }, proof: canaries.proof } }, 'sending messages')
	child.error({ stage: 'claimTunnel', outcome: 'success', errorCode: 'ERROR_NO_ERROR', err: nestedError }, canaries.error)
	const spoofRecord = JSON.parse(lines.at(-1)!) as Record<string, unknown>
	assert.equal(spoofRecord.stage, 'rpc')
	assert.equal(spoofRecord.outcome, 'failure')
	assert.equal(spoofRecord.errorCode, 'INTERNAL_ERROR')
	const throwing = new Proxy({}, { get() { throw new Error(canaries.error) } })
	assert.doesNotThrow(() => child.error(throwing, canaries.error))
	const records = assertPrivateLogs(lines)
	assert.ok(records.some(item => item.stage === 'init' && item.outcome === 'expired' && item.connectionRef === undefined))
	assert.ok(!lines.join('').includes(forgedRef), 'client-shaped correlation reference reached a log')
	loggerModule.makeLogger(false, 'info')
})

it('keeps non-auth pre-init send failures finite in actual Pino info and debug logs', async() => {
	const { handleMessage } = await import('#src/client/utils/message-handler.ts')
	for(const level of ['info', 'debug'] as const) {
		const { logger, lines } = capture(level)
		let sends = 0
		try {
			const socket = {
				logger: logger.child({ sessionId: canaries.auth, hostname: canaries.host }),
				isInitialised: false,
				async sendMessage() { sends++; throw nestedError },
				dispatchRPCEvent() { throw new Error('pre-init request reached a handler') }
			} as any
			const request = proto.RPCMessage.create({ id: canaries.requestId, createTunnelRequest: { id: 1, host: canaries.host, port: 443 } })
			assert.equal(handleMessage.call(socket, request), undefined)
			await delay(0)
			assert.equal(sends, 1)
			const records = assertPrivateLogs(lines)
			assert.equal(records.length, 2)
			assert.ok(records.every(item => item.stage === 'rpc' && item.outcome === 'failure'))
		} finally {
			loggerModule.makeLogger(false, 'info')
		}
	}
})
