import assert from 'node:assert/strict'
import { Socket } from 'node:net'
import { it, mock } from 'node:test'

process.env.CLAIM_EPOCH = '2'
delete process.env.HTTPS_PROXY_URL
delete process.env.ALLOWED_DIRECT_HOSTS

let resolveCalls = 0
let socketCalls = 0
mock.module('#src/server/utils/dns.ts', {
	namedExports: { async resolveHostnames() { resolveCalls++; return ['8.8.8.8'] } }
})
const connectMock = mock.method(Socket.prototype, 'connect', function(this: Socket) {
	socketCalls++
	setImmediate(() => this.emit('connect'))
	return this
})
const { makeTcpTunnel } = await import('#src/server/tunnels/make-tcp-tunnel.ts')
const logger = { info() {}, debug() {}, warn() {}, error() {} } as any

it('unset proxy configuration fails closed before DNS or direct socket', async() => {
	for(const extra of [{ geoLocation: 'US' }, { proxySessionId: 'session123' }]) {
		resolveCalls = 0
		socketCalls = 0
		await assert.rejects(
			makeTcpTunnel({ host: 'reviewed.example', port: 443, logger, ...extra } as any),
			/requires HTTPS_PROXY_URL/
		)
		assert.equal(resolveCalls, 0)
		assert.equal(socketCalls, 0)
	}
	connectMock.mock.restore()
})
