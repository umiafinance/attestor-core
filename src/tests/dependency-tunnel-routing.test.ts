import assert from 'node:assert/strict'
import { Socket } from 'node:net'
import { after, it, mock } from 'node:test'
import { Wallet } from 'ethers'

process.env.PRIVATE_KEY = Wallet.createRandom().privateKey
process.env.CLAIM_EPOCH = '2'
delete process.env.HTTPS_PROXY_URL
delete process.env.ALLOWED_DIRECT_HOSTS

let resolved: string[] = []
let resolveCalls = 0
const attempts: string[] = []
mock.module('#src/server/utils/dns.ts', {
	namedExports: { async resolveHostnames() { resolveCalls++; return resolved } }
})
const connectMock = mock.method(Socket.prototype, 'connect', function(this: Socket, opts: { host: string }) {
	attempts.push(opts.host)
	setImmediate(() => this.emit('connect'))
	return this
})
after(() => connectMock.mock.restore())
const { makeTcpTunnel } = await import('#src/server/tunnels/make-tcp-tunnel.ts')
const logger = { info() {}, debug() {}, warn() {}, error() {} } as any
const request = (host: string) => ({ host, port: 443, logger }) as any

it('connects only to a public DNS answer for direct tunnels', async() => {
	resolved = ['10.0.0.1', '8.8.8.8']
	resolveCalls = 0
	attempts.length = 0
	const tunnel = await makeTcpTunnel(request('reviewed.example'))
	assert.equal(resolveCalls, 1)
	assert.deepEqual(attempts, ['8.8.8.8'])
	tunnel.close()
})

it('does not connect when all answers are nonpublic or mixed with IPv6', async() => {
	for(const answers of [['10.0.0.1'], ['127.0.0.1'], ['8.8.8.8', '2606:4700:4700::1111']]) {
		resolved = answers
		attempts.length = 0
		await assert.rejects(makeTcpTunnel(request('reviewed.example')))
		assert.equal(attempts.length, 0)
	}
})
