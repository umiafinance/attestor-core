import assert from 'node:assert/strict'
import { Socket } from 'node:net'
import { it, mock } from 'node:test'
import { Wallet } from 'ethers'

process.env.PRIVATE_KEY = Wallet.createRandom().privateKey
process.env.CLAIM_EPOCH = '2'
process.env.HTTPS_PROXY_URL = 'http://127.0.0.1:1/{{geoLocation}}{{proxySessionId}}'
delete process.env.ALLOWED_DIRECT_HOSTS

let resolved: string[] = []
let dnsCalls = 0
const proxyCalls: Array<{ host: string, port: number }> = []
mock.module('#src/server/utils/dns.ts', {
	namedExports: { async resolveHostnames() { dnsCalls++; return resolved } }
})
mock.module('https-proxy-agent', {
	namedExports: {
		HttpsProxyAgent: class {
			constructor(_url: string) {}
			async connect(socket: Socket, opts: { host: string, port: number }) {
				proxyCalls.push({ host: opts.host, port: opts.port })
				process.nextTick(() => socket.emit('proxyConnect', { statusCode: 200, statusText: 'OK', headers: {} }))
				return socket
			}
		}
	}
})
const connectMock = mock.method(Socket.prototype, 'connect', () => {
	throw new Error('unexpected direct socket connection')
})
const { makeTcpTunnel } = await import('#src/server/tunnels/make-tcp-tunnel.ts')
const logger = { info() {}, debug() {}, warn() {}, error() {} } as any

it('configured geo proxy delegates original hostname and port without local DNS', async() => {
	dnsCalls = 0
	proxyCalls.length = 0
	const tunnel = await makeTcpTunnel({
		host: 'reviewed.example', port: 443, geoLocation: 'US', logger
	} as any)
	assert.equal(dnsCalls, 0)
	assert.deepEqual(proxyCalls, [{ host: 'reviewed.example', port: 443 }])
	tunnel.close()
})

it('configured geo and session proxy delegates original hostname without local DNS', async() => {
	dnsCalls = 0
	proxyCalls.length = 0
	const tunnel = await makeTcpTunnel({
		host: 'reviewed.example', port: 443, geoLocation: 'US', proxySessionId: 'session123', logger
	} as any)
	assert.equal(dnsCalls, 0)
	assert.deepEqual(proxyCalls, [{ host: 'reviewed.example', port: 443 }])
	tunnel.close()
})

it('session-only configured path does not reach proxy or direct socket', async() => {
	resolved = ['10.0.0.1', '8.8.8.8']
	dnsCalls = 0
	proxyCalls.length = 0
	await assert.rejects(makeTcpTunnel({
		host: 'reviewed.example', port: 443, proxySessionId: 'session123', logger
	} as any))
	assert.equal(dnsCalls, 1)
	assert.deepEqual(proxyCalls, [])
	connectMock.mock.restore()
})
