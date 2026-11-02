import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import type { AddressInfo } from 'node:net'
import { Writable } from 'node:stream'
import { afterEach, beforeEach, describe, it, mock } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { WebSocketServer } from 'ws'

import { BGP_EVENTS } from '#src/utils/diagnostic-events.ts'
import { makeLogger } from '#src/utils/logger.ts'

const CANARY = 'PRIVATE_HOST_AUTH_ERROR_PAYLOAD'
const NativeWebSocket = globalThis.WebSocket
let socketFactory = (url: string): WebSocket => new NativeWebSocket(url)

class FakeWebSocket {
	static OPEN = 1
	static instances: FakeWebSocket[] = []
	static failConstruction = false
	readyState = 0
	onopen: (() => void) | null = null
	onerror: (() => void) | null = null
	onclose: (() => void) | null = null
	onmessage: ((event: { data: string | { toString(): string } }) => void) | null = null
	sent: string[] = []
	closes = 0
	failSend = false
	failClose = false
	constructor(_url: string) {
		if(FakeWebSocket.failConstruction) throw new Error(CANARY)
		FakeWebSocket.instances.push(this)
	}
	send(value: string) {
		if(this.readyState !== FakeWebSocket.OPEN) throw new DOMException('Sent before connected.', 'InvalidStateError')
		if(this.failSend) throw new DOMException(CANARY, 'InvalidStateError')
		this.sent.push(value)
	}
	close() {
		this.closes++
		if(this.failClose) throw new Error(CANARY)
		this.readyState = 3
	}
	open() { this.readyState = FakeWebSocket.OPEN; this.onopen?.() }
}

mock.module('#src/utils/ws.ts', {
	namedExports: { makeWebSocket: (url: string) => socketFactory(url) }
})
const { createBgpListener } = await import('#src/utils/bgp-listener.ts')

function capture() {
	const lines: string[] = []
	const stream = new Writable({ write(chunk, _encoding, done) { lines.push(chunk.toString()); done() } })
	return { logger: makeLogger(false, 'trace', undefined, stream), lines }
}

describe('BGP socket lifecycle', () => {
	let listener: ReturnType<typeof createBgpListener> | undefined
	let logs: ReturnType<typeof capture>
	beforeEach(() => {
		FakeWebSocket.instances = []
		FakeWebSocket.failConstruction = false
		socketFactory = url => new FakeWebSocket(url) as unknown as WebSocket
		mock.timers.enable({ apis: ['setTimeout'] })
		logs = capture()
	})
	afterEach(() => {
		listener?.close()
		listener = undefined
		mock.timers.reset()
		socketFactory = url => new NativeWebSocket(url)
		makeLogger(false, 'info')
	})

	function start() {
		listener = createBgpListener(logs.logger)
		return FakeWebSocket.instances.at(-1)!
	}

	it('ignores queued events from retired sockets and subscribes only the owning open socket', () => {
		const a = start()
		const lateOpen = a.onopen!
		const lateError = a.onerror!
		const lateClose = a.onclose!
		const lateMessage = a.onmessage!
		let overlaps = 0
		listener!.onOverlap(['203.0.113.7'], () => overlaps++)
		lateError()
		assert.doesNotThrow(lateOpen)
		lateClose()
		assert.equal(a.closes, 1)
		assert.equal(a.onopen, null)
		assert.equal(a.onmessage, null)
		assert.equal(a.onerror, null)
		assert.equal(a.onclose, null)
		mock.timers.tick(999)
		assert.equal(FakeWebSocket.instances.length, 1)
		mock.timers.tick(1)
		const b = FakeWebSocket.instances[1]
		assert.equal(b.readyState, 0)
		assert.doesNotThrow(lateOpen)
		lateError()
		lateClose()
		lateMessage({ data: JSON.stringify({ data: { path: ['test'], announcements: [{ prefixes: ['203.0.113.0/24'] }] } }) })
		assert.equal(overlaps, 0)
		assert.deepEqual(a.sent, [])
		assert.deepEqual(b.sent, [])
		b.open()
		assert.deepEqual(b.sent.map(value => JSON.parse(value)), [{ type: 'ris_subscribe', data: { type: 'UPDATE' } }])
		mock.timers.tick(60_000)
		assert.equal(FakeWebSocket.instances.length, 2)
	})

	it('guards a non-OPEN subscription and recovers after a thrown send', () => {
		const a = start()
		assert.doesNotThrow(() => a.onopen!())
		assert.deepEqual(a.sent, [])
		mock.timers.tick(1_000)
		const b = FakeWebSocket.instances[1]
		b.failSend = true
		b.failClose = true
		assert.doesNotThrow(() => b.open())
		assert.equal(b.closes, 1)
		mock.timers.tick(2_000)
		const c = FakeWebSocket.instances[2]
		c.open()
		assert.equal(c.sent.length, 1)
		const reasons = logs.lines.map(line => JSON.parse(line).reason)
		assert.ok(reasons.includes('BGP_NOT_OPEN'))
		assert.ok(reasons.includes('BGP_SUBSCRIBE_FAILED'))
		assert.ok(reasons.includes('BGP_CLOSE_FAILED'))
		assert.ok(!logs.lines.join('').includes(CANARY))
	})

	it('backs off constructor failures up to 30s and resets after a successful subscription', () => {
		FakeWebSocket.failConstruction = true
		assert.doesNotThrow(start)
		for(const wait of [1_000, 2_000, 4_000, 8_000, 16_000, 30_000]) mock.timers.tick(wait)
		FakeWebSocket.failConstruction = false
		mock.timers.tick(29_999)
		assert.equal(FakeWebSocket.instances.length, 0)
		mock.timers.tick(1)
		const a = FakeWebSocket.instances[0]
		a.open()
		a.onclose!()
		mock.timers.tick(999)
		assert.equal(FakeWebSocket.instances.length, 1)
		mock.timers.tick(1)
		assert.equal(FakeWebSocket.instances.length, 2)
	})

	it('cancels pending retries when closed', () => {
		const a = start()
		a.onerror!()
		listener!.close()
		listener!.close()
		mock.timers.tick(60_000)
		assert.equal(FakeWebSocket.instances.length, 1)
		assert.equal(a.closes, 1)
	})

	it('ignores all queued callbacks after shutdown even when socket.close throws', () => {
		const a = start()
		const callbacks = [a.onopen!, a.onerror!, a.onclose!]
		const message = a.onmessage!
		a.failClose = true
		assert.doesNotThrow(() => listener!.close())
		for(const callback of callbacks) assert.doesNotThrow(callback)
		assert.doesNotThrow(() => message({ data: { toString() { throw new Error(CANARY) } } }))
		mock.timers.tick(60_000)
		assert.equal(FakeWebSocket.instances.length, 1)
	})

	it('contains malformed feed messages and keeps delivering current-socket overlaps', () => {
		const a = start()
		let overlaps = 0
		const unsubscribe = listener!.onOverlap(['203.0.113.7'], () => overlaps++)
		for(const data of ['not json', { toString() { throw new Error(CANARY) } }, JSON.stringify({ data: { path: ['test'], announcements: [{ prefixes: [null] }] } })]) {
			assert.doesNotThrow(() => a.onmessage!({ data }))
		}
		const update = JSON.stringify({ data: { path: ['test'], announcements: [{ prefixes: ['203.0.113.0/24'] }] } })
		a.onmessage!({ data: update })
		assert.equal(overlaps, 1)
		unsubscribe()
		a.onmessage!({ data: update })
		assert.equal(overlaps, 1)
		const records = logs.lines.map(line => JSON.parse(line))
		assert.ok(records.every(record => record.stage === 'bgp'))
		assert.equal(records.filter(record => record.reason === 'BGP_MESSAGE_INVALID').length, 3)
		assert.ok(!logs.lines.join('').includes(CANARY))
	})
})

it('keeps trusted BGP diagnostics independent of wording and rejects client-shaped event copies', () => {
	const { logger, lines } = capture()
	try {
		for(const message of [undefined, CANARY, 'handled RPC request']) {
			logger.warn({ event: BGP_EVENTS.closed }, message)
			const record = JSON.parse(lines.at(-1)!)
			assert.equal(record.stage, 'bgp')
			assert.equal(record.outcome, 'failure')
			assert.equal(record.reason, 'BGP_CLOSED')
		}

		logger.warn({ event: { ...BGP_EVENTS.closed }, reason: 'BGP_CLOSED' }, CANARY)
		const forged = JSON.parse(lines.at(-1)!)
		assert.equal(forged.stage, 'rpc')
		assert.equal(forged.reason, undefined)
		assert.ok(!lines.join('').includes(CANARY))
	} finally {
		makeLogger(false, 'info')
	}
})

it('records finite network failure reasons for RPCs without exposing error messages', () => {
	const { logger, lines } = capture()
	try {
		for(const [code, reason] of [
			['ECONNRESET', 'CONNECTION_RESET'], ['EPIPE', 'BROKEN_PIPE'],
			['ECONNREFUSED', 'CONNECTION_REFUSED'], ['ETIMEDOUT', 'CONNECTION_TIMEOUT'],
			['UND_ERR_CONNECT_TIMEOUT', 'CONNECTION_TIMEOUT'], ['ENOTFOUND', 'DNS_LOOKUP_FAILED'],
			['EAI_AGAIN', 'DNS_LOOKUP_FAILED'], ['ENETUNREACH', 'NETWORK_UNREACHABLE'],
			['EHOSTUNREACH', 'NETWORK_UNREACHABLE'], [CANARY, undefined]
		]) {
			logger.error({ err: Object.assign(new Error(CANARY), { code, hostname: CANARY }) }, 'error in RPC request')
			const record = JSON.parse(lines.at(-1)!)
			assert.equal(record.stage, 'rpc')
			assert.equal(record.outcome, 'failure')
			assert.equal(record.errorCode, 'INTERNAL_ERROR')
			assert.equal(record.reason, reason)
		}

		logger.error({ err: new DOMException(CANARY, 'InvalidStateError') }, 'error in RPC request')
		assert.equal(JSON.parse(lines.at(-1)!).reason, 'INVALID_STATE')
		assert.ok(!lines.join('').includes(CANARY))
	} finally {
		makeLogger(false, 'info')
	}
})

it('reconnects and resubscribes using the real Node WebSocket against a loopback feed', async() => {
	const server = new WebSocketServer({ port: 0, host: '127.0.0.1' })
	await new Promise<void>(resolve => server.once('listening', resolve))
	const url = `ws://127.0.0.1:${(server.address() as AddressInfo).port}`
	const { logger, lines } = capture()
	let listener: ReturnType<typeof createBgpListener> | undefined
	let subscriptions = 0
	let overlaps = 0
	server.on('connection', socket => socket.on('message', value => {
		assert.deepEqual(JSON.parse(value.toString()), { type: 'ris_subscribe', data: { type: 'UPDATE' } })
		subscriptions++
		if(subscriptions === 1) socket.terminate()
		else socket.send(JSON.stringify({ data: { path: ['test'], announcements: [{ prefixes: ['203.0.113.0/24'] }] } }))
	}))
	try {
		socketFactory = () => new NativeWebSocket(url)
		listener = createBgpListener(logger)
		listener.onOverlap(['203.0.113.7'], () => overlaps++)
		const deadline = Date.now() + 5_000
		while(overlaps === 0 && Date.now() < deadline) await delay(20)
		assert.equal(subscriptions, 2)
		assert.equal(overlaps, 1)
		assert.ok(lines.map(line => JSON.parse(line)).every(record => record.stage === 'bgp'))
	} finally {
		listener?.close()
		socketFactory = url => new NativeWebSocket(url)
		for(const socket of server.clients) socket.terminate()
		await new Promise<void>(resolve => server.close(() => resolve()))
		makeLogger(false, 'info')
	}
})

// A subprocess timeout bounds this regression even if the vulnerable parser returns.
it('rejects oversized IPv6 zone identifiers without blocking the process', () => {
	const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
		import assert from 'node:assert/strict'
		import { Address6 } from 'ip-address'
		const input = 'fe80::1' + '%'.repeat(1_000_000) + '\\n'
		assert.throws(() => new Address6(input))
		assert.equal(Address6.isValid(input), false)
	`], { timeout: 5_000, encoding: 'utf8', cwd: new URL('../../', import.meta.url) })
	assert.ifError(child.error)
	assert.equal(child.status, 0, child.stderr)
})
