import assert from 'node:assert/strict'
import { setTimeout as delay } from 'node:timers/promises'
import { it } from 'node:test'
import { Wallet } from 'ethers'

process.env.CLAIM_EPOCH = '2'

process.env.CLAIM_CHAIN_IDS = '10143'
process.env.PRIVATE_KEY = '0x0000000000000000000000000000000000000000000000000000000000000001'
process.env.DISABLE_BGP_CHECKS = '1'

const [{ AttestorClient }, { WS_PATHNAME }, { createServer }, { getRandomPort }, { createAuthRequest }, { AttestorError }] = await Promise.all([
	import('#src/client/utils/client-socket.ts'),
	import('#src/config/index.ts'),
	import('#src/server/create-server.ts'),
	import('#src/tests/utils.ts'),
	import('#src/utils/auth.ts'),
	import('#src/utils/error.ts')
])

function isAuthError(err: unknown) {
	return err instanceof AttestorError && err.code === 'ERROR_AUTHENTICATION_FAILED'
}

function isRejectedInit(err: unknown) {
	return isAuthError(err)
		|| err instanceof AttestorError
			&& err.code === 'ERROR_NETWORK_ERROR'
			&& err.message === 'connection closed'
}

it('rejects bad WS init and closes an active tunnel at fixed expiry despite activity', async() => {
	const key = Wallet.createRandom()
	process.env.AUTHENTICATION_PUBLIC_KEY = key.publicKey
	const port = getRandomPort()
	const server = await createServer(port)
	const url = `ws://127.0.0.1:${port}${WS_PATHNAME}`
	let a: InstanceType<typeof AttestorClient> | undefined
	let b: InstanceType<typeof AttestorClient> | undefined
	try {
		const missing = new AttestorClient({ url })
		await assert.rejects(missing.waitForInit(), isRejectedInit)
		assert.equal(missing.isInitialised, false)
		const wrong = await createAuthRequest(
			{ id: 'wrong', hostWhitelist: ['example.com'] },
			Wallet.createRandom().privateKey
		)
		const invalid = new AttestorClient({ url, authRequest: wrong })
		await assert.rejects(invalid.waitForInit(), isRejectedInit)
		assert.equal(invalid.isInitialised, false)
		assert.equal([...server.clients].some(ws => ws.serverSocket), false)
		for(const hostWhitelist of [[], ['*.example.com'], ['API.example.com'],
			['other.example.com', 'example.com'], ['example.com', 'example.com']]) {
			const signed = await createAuthRequest({ id: 'bad-hosts', hostWhitelist }, key.privateKey)
			const rejected = new AttestorClient({ url, authRequest: signed })
			try {
				await assert.rejects(rejected.waitForInit(),
					(err: AttestorError) => err.code === 'ERROR_BAD_REQUEST')
			} finally {
				await rejected.terminateConnection()
			}
		}

		const expiresAt = Math.floor(Date.now() / 1000) + 3
		const authA = await createAuthRequest(
			{ id: 'a', hostWhitelist: ['example.com'], expiresAt }, key.privateKey
		)
		const authB = await createAuthRequest(
			{ id: 'b', hostWhitelist: ['example.com'], expiresAt: expiresAt + 10 }, key.privateKey
		)
		a = new AttestorClient({ url, authRequest: authA })
		await a.waitForInit()
		const wsA = [...server.clients].find(ws => ws.serverSocket?.authIdentity === 'a')
		assert.ok(wsA)
		const socketA = wsA.serverSocket
		assert.ok(socketA)
		assert.equal(socketA.authIdentity, 'a')
		assert.deepEqual(socketA.authHostWhitelist, ['example.com'])
		assert.equal(Object.isFrozen(socketA.authHostWhitelist), true)
		authA.data!.hostWhitelist.push('another.example')
		assert.deepEqual(socketA.authHostWhitelist, ['example.com'])

		b = new AttestorClient({ url, authRequest: authB })
		await b.waitForInit()
		const wsB = [...server.clients].find(ws => ws.serverSocket?.authIdentity === 'b')
		assert.ok(wsB)
		const socketB = wsB.serverSocket
		assert.ok(socketB)
		let writes = 0
		let closes = 0
		const activeTunnel = {
			async write() { writes++ },
			async close() { closes++ },
			createRequest: { host: 'example.com', port: 443, geoLocation: '', proxySessionId: '' }, transcript: []
		}
		socketA.tunnels[7] = activeTunnel
		const activity = setInterval(() => {
			if(wsA.readyState === wsA.OPEN) wsA.ping()
			void a?.sendMessage({ tunnelMessage: { tunnelId: 7, message: new Uint8Array([1]) } }).catch(() => {})
		}, 100)
		try {
			while(Date.now() < expiresAt * 1000 + 250) await delay(50)
		} finally {
			clearInterval(activity)
		}
		assert.ok(writes > 0)
		assert.equal(a.isClosed, true)
		assert.equal(closes, 1)
		assert.deepEqual(socketA.tunnels, {})
		socketA.tunnels[7] = activeTunnel
		const writesAfterExpiry = writes
		socketA.dispatchRPCEvent('tunnel-message', { tunnelId: 7, message: new Uint8Array([1]) })
		await delay(0)
		assert.equal(writes, writesAfterExpiry)
		delete socketA.tunnels[7]
		assert.equal(b.isOpen, true)
		await assert.rejects(
			socketA.sendMessage({ tunnelMessage: { tunnelId: 7, message: new Uint8Array([1]) } }),
			isAuthError
		)
		await b.sendMessage({ connectionTerminationAlert: new AttestorError('ERROR_NO_ERROR', '').toProto() })
		for(let i = 0; i < 40 && !b.isClosed; i++) await delay(10)
		assert.equal(b.isClosed, true)
		assert.throws(() => socketB.assertAuthActive(), isAuthError)
	} finally {
		await a?.terminateConnection()
		await b?.terminateConnection()
		await new Promise<void>(resolve => server.close(() => resolve()))
		delete process.env.AUTHENTICATION_PUBLIC_KEY
	}
})
