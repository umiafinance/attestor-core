import assert from 'node:assert/strict'
import { it, mock } from 'node:test'

import type { makeTcpTunnel } from '#src/server/tunnels/make-tcp-tunnel.ts'
import { CreateTunnelRequest, InitRequest, ServiceSignatureType } from '#src/proto/api.ts'

process.env.CLAIM_EPOCH = '2'
process.env.PRIVATE_KEY = '0x0000000000000000000000000000000000000000000000000000000000000001'
delete process.env.AUTHENTICATION_PUBLIC_KEY

let dialCount = 0
mock.module('#src/server/tunnels/make-tcp-tunnel.ts', {
	namedExports: {
		async makeTcpTunnel(opts: Parameters<typeof makeTcpTunnel>[0]) {
			dialCount++
			return { createRequest: opts, transcript: [], async close() {} }
		}
	}
})

const [{ init }, { createTunnel }] = await Promise.all([
	import('#src/server/handlers/init.ts'),
	import('#src/server/handlers/createTunnel.ts')
])
const logger = { child() { return logger }, info() {}, debug() {}, warn() {}, error() {} }

it('rejects tunnels from a session initialised without AUTHENTICATION_PUBLIC_KEY', async() => {
	const client = {
		isInitialised: false, isOpen: true, tunnels: {}, logger,
		authHostWhitelist: undefined as readonly string[] | undefined,
		setAuthSession(data: { hostWhitelist: string[] }) { this.authHostWhitelist = data.hostWhitelist },
		assertAuthActive() {}, async sendMessage() {}
	}
	await init(InitRequest.create({ signatureType: ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH, clientVersion: 1 }),
		{ client, logger } as unknown as Parameters<typeof init>[1])
	assert.equal(client.isInitialised, true)

	await assert.rejects(
		createTunnel(CreateTunnelRequest.create({ id: 1, host: 'api.example.com', port: 443 }),
			{ client, logger } as unknown as Parameters<typeof createTunnel>[1]),
		{ code: 'ERROR_AUTHENTICATION_FAILED' }
	)
	assert.equal(dialCount, 0)
	assert.deepEqual(client.tunnels, {})
})
