import assert from 'node:assert/strict'
import { once } from 'node:events'
import { it } from 'node:test'
import type { IncomingMessage } from 'node:http'
import { Wallet } from 'ethers'
import { WebSocket } from 'ws'

import { RPCMessages } from '#src/proto/api.ts'
import { InvalidRpcFrameError } from '#src/utils/rpc-frame.ts'

process.env.CLAIM_EPOCH = '2'
process.env.CLAIM_CHAIN_IDS = '10143'
process.env.PRIVATE_KEY = '0x0000000000000000000000000000000000000000000000000000000000000001'
process.env.DISABLE_BGP_CHECKS = '1'
const issuer = Wallet.createRandom()
process.env.AUTHENTICATION_PUBLIC_KEY = issuer.publicKey

const [
	{ createServer }, { AttestorClient }, { createAuthRequest }, { getRandomPort },
	{ getInitialMessagesFromQuery }, { wsMessageHandler, handleMessage },
] = await Promise.all([
	import('#src/server/create-server.ts'), import('#src/client/utils/client-socket.ts'),
	import('#src/utils/auth.ts'), import('#src/tests/utils.ts'),
	import('#src/server/utils/generics.ts'), import('#src/client/utils/message-handler.ts'),
])

it('applies the same bound to upgrade-query messages', () => {
	const bytes = Buffer.alloc(66, Buffer.from([10, 0]))
	const req = { url: `/ws?messages=${encodeURIComponent(bytes.toString('base64'))}` } as IncomingMessage
	assert.throws(() => getInitialMessagesFromQuery(req), InvalidRpcFrameError)
})

it('rejects the entire batch before dispatch or per-entry logging', async() => {
	let terminations = 0
	const unexpected = () => assert.fail('invalid batch was dispatched or logged')
	const client = {
		isClosed: false,
		logger: { trace: unexpected, warn: unexpected },
		dispatchRPCEvent: unexpected,
		async terminateConnection(err: Error) {
			assert.ok(err instanceof InvalidRpcFrameError)
			terminations++
		},
	} as unknown as ThisParameterType<typeof wsMessageHandler>
	const valid = RPCMessages.encode(RPCMessages.create({ messages: [{ createTunnelResponse: {} }] })).finish()
	await wsMessageHandler.call(client, Buffer.concat([valid, Buffer.from([10, 0])]))
	assert.equal(terminations, 1)
	// A direct caller also closes for an unhandled entry without logging its contents.
	client.logger.trace = () => {}
	await handleMessage.call(client, { id: 1 })
	assert.equal(terminations, 2)
})

it('closes malformed and oversized batches, releases auth slots, and keeps serving valid clients', { timeout: 15_000 }, async() => {
	const port = getRandomPort()
	const server = await createServer(port)
	const url = `ws://127.0.0.1:${port}/ws`
	const authRequest = await createAuthRequest({ id: 'rpc-frame-session', hostWhitelist: ['example.com'] }, issuer.privateKey)
	const sockets: WebSocket[] = []
	try {
		// More than four successive authenticated sockets also tests slot release on rejection.
		for(const payload of [
			Buffer.alloc(4 * 1024 * 1024, Buffer.from([10, 0])),
			Buffer.from([10, 0]), Buffer.from([10, 3, 208, 1, 0]),
			Buffer.from([10, 128]), Buffer.from([10, 2, 56, 0]),
		]) {
			let socket!: WebSocket
			const client = new AttestorClient({ url, authRequest, makeWebSocket: target => {
				socket = new WebSocket(target)
				sockets.push(socket)
				return socket
			} })
			await client.waitForInit()
			const closed = once(socket, 'close')
			socket.send(payload)
			await closed
			assert.equal(client.isClosed, true)
		}
		const anonymous = new WebSocket(url)
		sockets.push(anonymous)
		await once(anonymous, 'open')
		const closed = once(anonymous, 'close')
		anonymous.send(Buffer.alloc(64 * 1024, Buffer.from([10, 0])))
		await closed

		const query = Buffer.alloc(66, Buffer.from([10, 0])).toString('base64')
		const invalidQuery = new WebSocket(`${url}?messages=${encodeURIComponent(query)}`)
		sockets.push(invalidQuery)
		await once(invalidQuery, 'close')

		const healthy = new AttestorClient({ url, authRequest, makeWebSocket: target => new WebSocket(target) })
		try {
			await healthy.waitForInit()
			assert.equal(healthy.isOpen, true)
		} finally {
			await healthy.terminateConnection()
		}
	} finally {
		for(const socket of sockets) socket.terminate()
		for(const socket of server.clients) socket.terminate()
		await new Promise<void>(resolve => server.close(() => resolve()))
	}
})
