import assert from 'node:assert/strict'
import { it } from 'node:test'

import { createBgpListener } from '#src/utils/bgp-listener.ts'

class FakeWebSocket {
	static last: FakeWebSocket
	onmessage?: (event: { data: string }) => void
	onopen?: () => void
	onclose?: () => void
	onerror?: () => void
	constructor(_url: string) { FakeWebSocket.last = this }
	send(_value: string) {}
	close() {}
	announce(prefix: string) {
		this.onmessage?.({ data: JSON.stringify({
			data: { path: ['test'], announcements: [{ prefixes: [prefix], next_hop: 'test' }] }
		}) })
	}
}

it('preserves BGP same-family containment and fails closed on invalid prefixes', () => {
	const originalWebSocket = globalThis.WebSocket
	globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket
	let errors = 0
	const logger = {
		info() {}, debug() {}, trace() {}, warn() {}, error() { errors++ }
	} as any
	try {
		for(const [prefix, target, expected] of [
			['203.0.113.0/24', '203.0.113.255', true],
			['203.0.113.0/24', '203.0.114.1', false],
			['203.0.113.7/32', '203.0.113.7', true],
			['203.0.113.7/32', '203.0.113.8', false],
			['203.0.113.8/31', '203.0.113.9', true],
			['203.0.113.8/31', '203.0.113.10', false],
			['2001:db8::/32', '2001:db8:ffff::1', true],
			['2001:db8::/32', '2001:db9::1', false],
			['2001:db8::7/128', '2001:db8::7', true],
			['2001:db8::7/128', '2001:db8::8', false],
			['2001:db8::8/127', '2001:db8::9', true],
			['2001:db8::8/127', '2001:db8::a', false],
			['203.0.113.0/24', '2001:db8::7', false],
			['2001:db8::/32', '203.0.113.7', false],
			['203.0.113.0/24', 'invalid-target', false],
			['2001:db8::/32', 'invalid-target', false],
			['0.0.0.0/0', '203.0.113.7', false],
			['::/0', '2001:db8::7', false],
			['bad-prefix', '203.0.113.7', false],
			['012.0.0.0/8', '10.0.0.1', false],
			['2001:db8::/129', '2001:db8::7', false]
		] as const) {
			let hits = 0
			const listener = createBgpListener(logger)
			listener.onOverlap([target], () => { hits++ })
			FakeWebSocket.last.announce(prefix)
			assert.equal(hits > 0, expected, `${prefix} -> ${target}`)
			listener.close()
		}
		assert.ok(errors >= 2)
	} finally {
		globalThis.WebSocket = originalWebSocket
	}
})
