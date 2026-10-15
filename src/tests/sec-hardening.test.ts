import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createPrivateKey, webcrypto } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { connect, createServer as createNetServer } from 'node:net'
import type { AddressInfo } from 'node:net'
import { after, describe, it } from 'node:test'
import { connect as tlsConnect, createServer as createTlsServer } from 'node:tls'
import * as x509 from '@peculiar/x509'
import { Wallet } from 'ethers'
import { WebSocket } from 'ws'

import { RPCMessages, TranscriptMessageSenderType } from '#src/proto/api.ts'
import { SEC_HARDENING_REASONS } from '#src/tests/utils/sec-hardening-reasons.ts'

process.env.CLAIM_EPOCH = '2'
process.env.CLAIM_CHAIN_IDS = '10143'
process.env.PRIVATE_KEY = '0x0000000000000000000000000000000000000000000000000000000000000001'
process.env.DISABLE_BGP_CHECKS = '1'

const [
	{ REJECTION_REASONS, rejectionReason },
	{ AttestorError },
	{ processHandshake },
	{ fetchCertificateBytes },
	{ toprf },
	{ assertValidAuthRequest, createAuthRequest },
	{ AttestorClient },
	{ INIT_TIMEOUT_MS, MAX_AUTHENTICATED_WS_PAYLOAD_BYTES, MAX_PRE_AUTH_WS_PAYLOAD_BYTES, MAX_SOCKETS_PER_AUTH, WS_PATHNAME },
	{ createServer },
	{ getRandomPort },
	{ SelectedServiceSignatureType },
] = await Promise.all([
	import('#src/utils/rejection-reason.ts'),
	import('#src/utils/error.ts'),
	import('#src/server/utils/process-handshake.ts'),
	import('#src/server/handlers/fetchCertificateBytes.ts'),
	import('#src/server/handlers/toprf.ts'),
	import('#src/utils/auth.ts'),
	import('#src/client/utils/client-socket.ts'),
	import('#src/config/index.ts'),
	import('#src/server/create-server.ts'),
	import('#src/tests/utils.ts'),
	import('#src/utils/signatures/index.ts'),
])

const logger = { info() {}, debug() {}, warn() {}, error() {}, trace() {}, child() { return logger } } as any
const AIA_HOST = 'aia.example'
const exercised = new Set<string>()

after(() => {
	assert.deepEqual([...exercised].sort(), [...SEC_HARDENING_REASONS].sort())
	for(const reason of SEC_HARDENING_REASONS) assert.ok(Object.hasOwn(REJECTION_REASONS, reason), reason)
})

function within<T>(promise: Promise<T>, ms: number) {
	let timer: ReturnType<typeof setTimeout>
	const timeout = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`no outcome within ${ms} ms`)), ms) })
	return Promise.race([promise, timeout]).finally(() => clearTimeout(timer))
}

function assertReason(err: unknown, code: string, reason: string) {
	assert.ok(err instanceof AttestorError, String(err))
	assert.equal(err.code, code)
	assert.equal(rejectionReason(err), reason)
	exercised.add(reason)
	return true
}

/** A leaf whose issuer is reachable only through its AIA caIssuers URL. */
async function leafWithAiaOnlyIssuer() {
	x509.cryptoProvider.set(webcrypto as any)
	const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' }
	const issuerKeys = await webcrypto.subtle.generateKey(alg, true, ['sign', 'verify'])
	const leafKeys = await webcrypto.subtle.generateKey(alg, true, ['sign', 'verify'])
	const notBefore = new Date(Date.now() - 60_000)
	const notAfter = new Date(Date.now() + 3_600_000)
	const leaf = await x509.X509CertificateGenerator.create({
		serialNumber: '02',
		subject: `CN=${AIA_HOST}`,
		issuer: 'CN=Synthetic Issuer',
		notBefore,
		notAfter,
		signingAlgorithm: alg,
		publicKey: leafKeys.publicKey,
		signingKey: issuerKeys.privateKey,
		extensions: [
			new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: AIA_HOST }]),
			new x509.AuthorityInfoAccessExtension({ caIssuers: 'http://127.0.0.1:9/issuer.crt' })
		]
	})
	const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', leafKeys.privateKey))
	return { cert: leaf.toString('pem'), key: createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' }).export({ format: 'pem', type: 'pkcs8' }) }
}

/** Records a real TLS 1.2 handshake up to the server's plaintext Certificate message. */
async function recordTls12Handshake() {
	const { cert, key } = await leafWithAiaOnlyIssuer()
	const server = createTlsServer({ cert, key, maxVersion: 'TLSv1.2', ciphers: 'ECDHE-ECDSA-AES128-GCM-SHA256' })
	server.on('tlsClientError', () => {})
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
	const records: { sender: TranscriptMessageSenderType, message: Uint8Array }[] = []
	const relay = createNetServer(client => {
		const upstream = connect((server.address() as AddressInfo).port, '127.0.0.1')
		const split = (sender: TranscriptMessageSenderType) => {
			let pending = Buffer.alloc(0)
			return (chunk: Buffer) => {
				pending = Buffer.concat([pending, chunk])
				while(pending.length >= 5 && pending.length >= 5 + pending.readUInt16BE(3)) {
					const length = 5 + pending.readUInt16BE(3)
					records.push({ sender, message: new Uint8Array(pending.subarray(0, length)) })
					pending = pending.subarray(length)
				}
			}
		}
		const fromClient = split(TranscriptMessageSenderType.TRANSCRIPT_MESSAGE_SENDER_TYPE_CLIENT)
		const fromServer = split(TranscriptMessageSenderType.TRANSCRIPT_MESSAGE_SENDER_TYPE_SERVER)
		client.on('data', chunk => { fromClient(chunk); upstream.write(chunk) })
		upstream.on('data', chunk => { fromServer(chunk); client.write(chunk) })
		client.on('error', () => upstream.destroy())
		upstream.on('error', () => client.destroy())
	})
	await new Promise<void>(resolve => relay.listen(0, '127.0.0.1', resolve))
	await new Promise<void>(resolve => {
		const socket = tlsConnect({
			port: (relay.address() as AddressInfo).port,
			host: '127.0.0.1',
			servername: AIA_HOST,
			rejectUnauthorized: false,
			maxVersion: 'TLSv1.2'
		}, () => { socket.end(); resolve() })
		socket.on('error', () => resolve())
	})
	relay.close()
	server.close()
	return records
}

describe('certificate fetching', () => {
	it('refuses the fetchCertificateBytes RPC without a request', async(t) => {
		const fetchSpy = t.mock.method(globalThis, 'fetch', async() => new Response('', { status: 404 }))
		await assert.rejects(
			fetchCertificateBytes({ url: 'http://169.254.169.254/latest/meta-data/' }, {} as any),
			(err: unknown) => assertReason(err, 'ERROR_CERTIFICATE_FETCH_FAILED', 'CERTIFICATE_FETCH_DISABLED')
		)
		assert.equal(fetchSpy.mock.callCount(), 0)
	})

	it('refuses the AIA issuer fetch while verifying a claimed handshake', async(t) => {
		const transcript = await recordTls12Handshake()
		const fetchSpy = t.mock.method(globalThis, 'fetch', async() => new Response('', { status: 404 }))
		const cachedBefore = Object.keys(TLS_INTERMEDIATE_CA_CACHE)
		await assert.rejects(
			processHandshake(transcript as any, logger),
			(err: unknown) => assertReason(err, 'ERROR_CERTIFICATE_FETCH_FAILED', 'CERTIFICATE_FETCH_DISABLED')
		)
		assert.equal(fetchSpy.mock.callCount(), 0)
		assert.deepEqual(Object.keys(TLS_INTERMEDIATE_CA_CACHE), cachedBefore)
	})
})

describe('toprf', () => {
	it('refuses OPRF evaluation on client input', async() => {
		await assert.rejects(
			toprf({ maskedData: new Uint8Array(32), engine: 0 } as any, { logger } as any),
			(err: unknown) => assertReason(err, 'ERROR_BAD_REQUEST', 'TOPRF_DISABLED')
		)
	})
})

describe('auth lifetime', () => {
	it('admits at most 15 minutes after createdAt and createdAt at most 60 s ahead', async(t) => {
		const issuer = Wallet.createRandom()
		process.env.AUTHENTICATION_PUBLIC_KEY = issuer.publicKey
		const now = 1_800_000_000
		t.mock.method(Date, 'now', () => now * 1000)
		const auth = (createdAt: number, expiresAt: number, key = issuer.privateKey) => (
			createAuthRequest({ id: 'session', hostWhitelist: ['example.com'], createdAt, expiresAt }, key)
		)
		try {
			for(const [createdAt, expiresAt] of [[now, now + 900], [now + 60, now + 960], [now - 899, now + 1]]) {
				await assertValidAuthRequest(await auth(createdAt, expiresAt), SelectedServiceSignatureType)
			}
			for(const [createdAt, expiresAt] of [[now, now + 901], [now + 61, now + 120], [0, now + 60], [now + 30, now + 30], [now + 30, now + 20]]) {
				await assert.rejects(
					assertValidAuthRequest(await auth(createdAt, expiresAt), SelectedServiceSignatureType),
					(err: unknown) => assertReason(err, 'ERROR_AUTHENTICATION_FAILED', 'AUTH_LIFETIME_INVALID'),
					`${createdAt}..${expiresAt}`
				)
			}
			// The signature is checked first, so a forged long-lived auth reports AUTH_INVALID.
			await assert.rejects(
				assertValidAuthRequest(await auth(0, now + 60, Wallet.createRandom().privateKey), SelectedServiceSignatureType),
				(err: unknown) => rejectionReason(err) === 'AUTH_INVALID'
			)
		} finally {
			delete process.env.AUTHENTICATION_PUBLIC_KEY
		}
	})
})

describe('pre-init socket limits', () => {
	const issuer = Wallet.createRandom()
	const authRequest = (id = 'session') => createAuthRequest({ id, hostWhitelist: ['example.com'] }, issuer.privateKey)
	const tunnelMessage = (bytes: number) => RPCMessages.encode({
		messages: [{ id: 1, tunnelMessage: { tunnelId: 9, message: new Uint8Array(bytes) } }]
	}).finish()
	const closeCode = (client: InstanceType<typeof AttestorClient>) => new Promise<number>(resolve => (
		(client as any).socket.addEventListener('close', (event: { code: number }) => resolve(event.code))
	))

	async function withServer(test: (url: string) => Promise<void>) {
		process.env.AUTHENTICATION_PUBLIC_KEY = issuer.publicKey
		const port = getRandomPort()
		const server = await createServer(port)
		try {
			await test(`ws://127.0.0.1:${port}${WS_PATHNAME}`)
		} finally {
			server.close()
			delete process.env.AUTHENTICATION_PUBLIC_KEY
		}
	}

	it('terminates a socket that does not init in time and keeps an initialised one', () => withServer(async url => {
		const authed = new AttestorClient({ url, authRequest: await authRequest() })
		const idle = new WebSocket(url)
		try {
			await authed.waitForInit()
			const openedAt = Date.now()
			const alert = new Promise<unknown>((resolve, reject) => {
				idle.on('message', (data: Buffer) => {
					const msg = RPCMessages.decode(data).messages.find(m => m.connectionTerminationAlert)
					if(msg) resolve(AttestorError.fromProto(msg.connectionTerminationAlert!))
				})
				idle.on('close', () => reject(new Error('closed without an alert')))
			})
			const closed = new Promise<void>(resolve => idle.on('close', () => resolve()))
			assertReason(await within(alert, 2 * INIT_TIMEOUT_MS), 'ERROR_TIMEOUT', 'INIT_TIMEOUT')
			await within(closed, 1_000)
			assert.ok(Date.now() - openedAt >= INIT_TIMEOUT_MS - 50)
			assert.equal(authed.isOpen, true)
		} finally {
			idle.terminate()
			await authed.terminateConnection()
		}
	}))

	it('caps messages before a verified auth and admits claim-sized ones after it', () => withServer(async url => {
		const oversized = tunnelMessage(MAX_PRE_AUTH_WS_PAYLOAD_BYTES)
		const preAuth = new WebSocket(url)
		const authed = new AttestorClient({ url, authRequest: await authRequest(), makeWebSocket: target => new WebSocket(target) })
		try {
			await within(new Promise(resolve => preAuth.on('open', resolve)), 2_000)
			assert.equal(preAuth.extensions, '')
			const code = new Promise<number>(resolve => preAuth.on('close', resolve))
			preAuth.send(oversized)
			assert.equal(await within(code, 2_000), 1009)

			await authed.waitForInit()
			const authedSocket = (authed as any).socket as WebSocket
			assert.equal(authedSocket.extensions, '')
			await new Promise<void>((resolve, reject) => authedSocket.send(oversized, err => err ? reject(err) : resolve()))
			await new Promise(resolve => setTimeout(resolve, 250))
			assert.equal(authed.isOpen, true)

			// A reveal too large for the authenticated cap fails finitely; the server keeps serving.
			const closed = closeCode(authed)
			await (authed as any).socket.send(tunnelMessage(MAX_AUTHENTICATED_WS_PAYLOAD_BYTES))
			assert.equal(await within(closed, 5_000), 1009)
			const next = new AttestorClient({ url, authRequest: await authRequest() })
			await next.waitForInit()
			await next.terminateConnection()
		} finally {
			preAuth.terminate()
			await authed.terminateConnection()
		}
	}))

	it('caps concurrent sockets per auth ID and frees a slot on close', () => withServer(async url => {
		const auth = await authRequest()
		const clients = Array.from({ length: MAX_SOCKETS_PER_AUTH }, () => new AttestorClient({ url, authRequest: auth }))
		const other = new AttestorClient({ url, authRequest: await authRequest('other-session') })
		let extra: InstanceType<typeof AttestorClient> | undefined
		try {
			await Promise.all([...clients, other].map(client => client.waitForInit()))
			extra = new AttestorClient({ url, authRequest: auth })
			await assert.rejects(extra.waitForInit(), (err: unknown) => assertReason(err, 'ERROR_AUTHENTICATION_FAILED', 'AUTH_SOCKET_LIMIT'))
			const closed = closeCode(clients[0])
			await clients[0].terminateConnection()
			await within(closed, 2_000)
			await new Promise(resolve => setTimeout(resolve, 50))
			extra = new AttestorClient({ url, authRequest: auth })
			await extra.waitForInit()
		} finally {
			await Promise.all([...clients, other, extra].map(client => client?.terminateConnection()))
		}
	}))
})

describe('image entrypoint', () => {
	const entrypoint = new URL('../../entrypoint.sh', import.meta.url).pathname
	const KEY = `0x02${'a'.repeat(64)}`
	const baseEnv = {
		PATH: process.env.PATH,
		PRIVATE_KEY: '0x01',
		TOPRF_PUBLIC_KEY: '0x01',
		TOPRF_SHARE_PUBLIC_KEY: '0x01',
		TOPRF_SHARE_PRIVATE_KEY: '0x01',
		AUTHENTICATION_PUBLIC_KEY: KEY
	}
	const run = (overrides: Record<string, string | undefined>) => {
		const env = Object.fromEntries(Object.entries({ ...baseEnv, ...overrides }).filter(([, value]) => value !== undefined))
		return spawnSync('sh', [entrypoint, 'true'], { env, encoding: 'utf8' })
	}

	it('starts only with a production environment and a whole-value key', () => {
		for(const env of [{}, { NODE_ENV: 'production' }, { AUTHENTICATION_PUBLIC_KEY: `0x04${'B'.repeat(128)}` }]) {
			assert.equal(run(env).status, 0, JSON.stringify(env))
		}
		for(const env of [
			{ NODE_ENV: 'test' },
			{ NODE_ENV: 'development' },
			{ ALLOWED_DIRECT_HOSTS: 'localhost' },
			{ ALLOWED_DIRECT_HOSTS: '' },
			{ ACCEPT_CLAIM_PAYMENT_REQUESTS: '1' },
			{ AUTHENTICATION_PUBLIC_KEY: `0x02${'a'.repeat(63)}\n` },
			{ AUTHENTICATION_PUBLIC_KEY: `0x02${'a'.repeat(31)}\n${'a'.repeat(32)}` },
			{ AUTHENTICATION_PUBLIC_KEY: `0x02${'g'.repeat(64)}` },
			{ AUTHENTICATION_PUBLIC_KEY: undefined }
		]) {
			assert.notEqual(run(env).status, 0, JSON.stringify(env))
		}
	})

	it('keeps upstream env files out of the image context', () => {
		const ignored = readFileSync(new URL('../../.dockerignore', import.meta.url), 'utf8').split('\n')
		assert.ok(ignored.includes('.env*'))
	})
})
