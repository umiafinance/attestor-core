import assert from 'node:assert/strict'
import { setTimeout as delay } from 'node:timers/promises'
import { it, mock } from 'node:test'

import type { makeTcpTunnel } from '#src/server/tunnels/make-tcp-tunnel.ts'
import { CreateTunnelRequest } from '#src/proto/api.ts'
import { AttestorError } from '#src/utils/error.ts'

let onMessage: ((data: Uint8Array) => void) | undefined
let closes = 0
mock.module('#src/server/tunnels/make-tcp-tunnel.ts', {
	namedExports: {
		async makeTcpTunnel(opts: Parameters<typeof makeTcpTunnel>[0]) {
			onMessage = opts.onMessage
			return {
				createRequest: opts,
				transcript: [],
				async write() {},
				async close() { closes++ }
			}
		}
	}
})

const { createTunnel } = await import('#src/server/handlers/createTunnel.ts')
const logger = { info() {}, debug() {}, warn() {}, error() {} }

it('allows a tunnel packet before expiry and blocks TCP-to-WS forwarding after expiry', async() => {
	let active = true
	const sent: unknown[] = []
	const client = {
		tunnels: {},
		isOpen: true,
		authHostWhitelist: Object.freeze(['example.com']),
		assertAuthActive() {
			if(!active) throw new AttestorError('ERROR_AUTHENTICATION_FAILED', 'Authentication expired')
		},
		isAuthActive() { return active },
		async sendMessage(message: unknown) { sent.push(message) }
	}
	await createTunnel(CreateTunnelRequest.create({ id: 7, host: 'example.com', port: 443 }),
		{ client, logger } as unknown as Parameters<typeof createTunnel>[1])
	onMessage!(new Uint8Array([1]))
	await delay(0)
	assert.equal(sent.length, 1)
	active = false
	onMessage!(new Uint8Array([2]))
	await delay(0)
	assert.equal(sent.length, 1)
	assert.equal(closes, 0)
})
