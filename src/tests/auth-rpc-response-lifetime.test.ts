import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { describe, it } from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import type { AttestorServerSocket as ServerSocket } from '#src/server/socket.ts'

const runChild = promisify(execFile)
const SCENARIO_ENV = 'AUTH_RESPONSE_RACE_SCENARIO'

if(process.env[SCENARIO_ENV]) {
	await runScenario(process.env[SCENARIO_ENV])
} else {
	describe('RPC response delivery across auth expiry', () => {
		for(const scenario of ['handler-crosses-deadline', 'termination-alert-pending', 'success-send-terminates', 'pre-init-rejection-terminates']) {
			it(`${scenario} does not crash or deliver a useful result`, async() => {
				const { stdout } = await runChild(
					process.execPath,
					[
						'--unhandled-rejections=strict',
						'--experimental-strip-types',
						fileURLToPath(import.meta.url)
					],
					{
						env: { ...process.env, NODE_OPTIONS: '', [SCENARIO_ENV]: scenario },
						timeout: 10_000
					}
				)
				assert.ok(stdout.split('\n').includes(`PASS ${scenario}`))
			})
		}
	})
}

async function runScenario(scenario: string) {
	process.env.CLAIM_EPOCH = '2'
	process.env.CLAIM_CHAIN_IDS = '10143'
	process.env.PRIVATE_KEY = '0x0000000000000000000000000000000000000000000000000001'
	const { setCryptoImplementation } = await import('@reclaimprotocol/tls')
	const { webcryptoCrypto } = await import('@reclaimprotocol/tls/webcrypto')
	setCryptoImplementation(webcryptoCrypto)
	const [{ AttestorServerSocket }, { HANDLERS }, { handleMessage }, { authExpiredError }, { RPCMessages }, { AttestorError }] = await Promise.all([
		import('#src/server/socket.ts'),
		import('#src/server/handlers/index.ts'),
		import('#src/client/utils/message-handler.ts'),
		import('#src/server/utils/auth-session.ts'),
		import('#src/proto/api.ts'),
		import('#src/utils/error.ts')
	])

	function deferred() {
		let resolve!: () => void
		const promise = new Promise<void>(r => { resolve = r })
		return { promise, resolve }
	}

	class FakeSocket extends EventTarget {
		readonly OPEN = 1
		readonly CLOSING = 2
		readonly CLOSED = 3
		readyState = this.OPEN
		readonly sent: string[] = []
		readonly alertSent = deferred()
		readonly releaseAlert = deferred()
		private readonly holdAlert: boolean
		constructor(holdAlert: boolean) {
			super()
			this.holdAlert = holdAlert
		}
		async sendPromise(bytes: Uint8Array) {
			for(const msg of RPCMessages.decode(bytes).messages) {
				if(msg.connectionTerminationAlert) {
					this.sent.push('termination')
					this.alertSent.resolve()
					if(this.holdAlert) {await this.releaseAlert.promise}
				} else if(msg.createTunnelResponse) {
					this.sent.push('useful-result')
				} else {
					this.sent.push('other-response')
				}
			}
		}
		close() {
			this.readyState = this.CLOSED
			this.dispatchEvent(new Event('close'))
		}
	}

	const logger = { child() { return this }, trace() {}, debug() {}, info() {}, warn() {}, error() {} }
	function makeSession(identity: string, expiresAt: number, holdAlert: boolean) {
		const socket = new FakeSocket(holdAlert)
		// Use the real server socket and inherited handleMessage responder with a controlled transport.
		const server = Reflect.construct(AttestorServerSocket, [socket, 1, undefined, logger]) as ServerSocket
		Object.assign(server, { isInitialised: true, metadata: { signatureType: 1, clientVersion: 1 } })
		server.setAuthSession({ id: identity, createdAt: 1, expiresAt, hostWhitelist: ['example.com'] })
		return { server, socket }
	}

	const entered = deferred()
	const releaseHandler = deferred()
	let handlerCalls = 0
	HANDLERS.createTunnel = async(_request, { client }) => {
		handlerCalls++
		if(client.authIdentity === 'live' || scenario === 'success-send-terminates') {return {}}
		entered.resolve()
		await releaseHandler.promise
		return {}
	}
	async function assertLiveSession() {
		const live = makeSession('live', Math.floor(Date.now() / 1000) + 30, false)
		await handleMessage.call(live.server, {
			id: 2,
			createTunnelRequest: { id: 2, host: 'example.com', port: 443 }
		})
		assert.deepEqual(live.socket.sent, ['useful-result'])
		await live.server.terminateConnection()
	}

	if(scenario === 'pre-init-rejection-terminates') {
		const socket = new FakeSocket(true)
		const server = Reflect.construct(AttestorServerSocket, [socket, 1, undefined, logger]) as ServerSocket
		assert.equal(server.isInitialised, false)
		void server.terminateConnection(authExpiredError())
		await socket.alertSent.promise
		await handleMessage.call(server, {
			id: 1,
			createTunnelRequest: { id: 1, host: 'example.com', port: 443 }
		})
		assert.equal(server.isInitialised, false)
		assert.equal(handlerCalls, 0)
		assert.deepEqual(socket.sent, ['termination'])
		socket.releaseAlert.resolve()
		while(!server.isClosed) {await new Promise(resolve => setTimeout(resolve, 1))}
		await assertLiveSession()
		process.stdout.write(`PASS ${scenario}\n`)
		return
	}

	const expiresAt = Math.floor(Date.now() / 1000) + (scenario === 'handler-crosses-deadline' ? 2 : 30)
	const expired = makeSession('expired', expiresAt, true)
	if(scenario === 'success-send-terminates') {
		const assertAuthActive = expired.server.assertAuthActive.bind(expired.server)
		let checks = 0
		expired.server.assertAuthActive = () => {
			if(++checks === 3) {void expired.server.terminateConnection(authExpiredError())}
			assertAuthActive()
		}
	}
	const request = handleMessage.call(expired.server, {
		id: 1,
		createTunnelRequest: { id: 1, host: 'example.com', port: 443 }
	})
	assert.ok(request)
	if(scenario === 'success-send-terminates') {
		await request
	} else {
		const rejected = assert.rejects(request, (err: unknown) =>
			err instanceof AttestorError && err.code === 'ERROR_AUTHENTICATION_FAILED'
		)
		await entered.promise
		if(scenario === 'handler-crosses-deadline') {
			// Block timer callbacks so the post-handler deadline guard detects expiry first.
			while(Date.now() < expiresAt * 1000 + 20) {}
		} else if(scenario === 'termination-alert-pending') {
			void expired.server.terminateConnection(authExpiredError())
			await expired.socket.alertSent.promise
		} else {
			throw new Error('unknown scenario')
		}
		releaseHandler.resolve()
		await rejected
	}
	await expired.socket.alertSent.promise
	assert.deepEqual(expired.socket.sent, ['termination'])
	expired.socket.releaseAlert.resolve()
	while(!expired.server.isClosed) {await new Promise(resolve => setTimeout(resolve, 1))}

	await assertLiveSession()
	process.stdout.write(`PASS ${scenario}\n`)
}
