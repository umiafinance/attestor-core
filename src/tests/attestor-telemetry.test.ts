import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer as createHttpServer, type IncomingHttpHeaders } from 'node:http'
import type { AddressInfo } from 'node:net'
import { Writable } from 'node:stream'
import { setTimeout as delay } from 'node:timers/promises'
import { after, before, describe, it, mock } from 'node:test'
import { MetricReader, type ResourceMetrics } from '@opentelemetry/sdk-metrics'
import { Wallet } from 'ethers'
import { WebSocket } from 'ws'

import { inputContext, signedContext, TEST_AUCTION_ADDRESS, TEST_CONTEXT_ADDRESS, TEST_CONTEXT_MESSAGE, TEST_PROVIDER_HASH, testAuthIdentity } from '#src/tests/utils/claim-context.ts'
import { canonicalStringify } from '#src/utils/claims.ts'

process.env.CLAIM_EPOCH = '2'
process.env.CLAIM_CHAIN_IDS = '10143'
process.env.PRIVATE_KEY = '0x0000000000000000000000000000000000000000000000000000000000000001'
process.env.DISABLE_BGP_CHECKS = '1'

const SESSION_ID = randomUUID()
const HASHES = [TEST_PROVIDER_HASH, `0x${'b'.repeat(64)}`]
const AUTH_ID = testAuthIdentity(TEST_CONTEXT_MESSAGE, TEST_CONTEXT_ADDRESS, SESSION_ID, HASHES.join(','))
const SIGNER = '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'
const canaries = {
	host: 'canary-host-private.example', tunnelHost: 'canary-tunnel-private.example',
	owner: 'canary-owner-private', error: 'CANARY_ERROR_PRIVATE', account: 'CANARY_ACCOUNT_PRIVATE'
}
const PRIVATE_VALUES = [
	...Object.values(canaries), SESSION_ID, AUTH_ID, ...HASHES, AUTH_ID.split(':').at(-1)!,
	TEST_CONTEXT_ADDRESS, TEST_AUCTION_ADDRESS, TEST_CONTEXT_MESSAGE
]

const claimInfo = {
	provider: 'http', parameters: canonicalStringify({ url: 'https://example.com/', secret: canaries.account }),
	context: signedContext(canaries.account, SESSION_ID), owner: canaries.owner,
	timestampS: Math.floor(Date.now() / 1000)
}
let rejectClaim = false
mock.module('#src/server/utils/assert-valid-claim-request.ts', {
	namedExports: {
		assertTranscriptsMatch() {},
		async assertValidClaimRequest() {
			if(rejectClaim) {
				const { rejection } = await import('#src/utils/rejection-reason.ts')
				throw rejection('ERROR_INVALID_CLAIM', 'TRANSCRIPT_DECRYPT_FAILED', canaries.error)
			}

			return { ...claimInfo }
		},
		async assertValidProviderTranscript() {
			return { ...claimInfo }
		}
	}
})

const [
	telemetry, loggerModule, { AttestorClient }, { WS_PATHNAME }, { createServer }, { getRandomPort },
	{ createAuthRequest }, { claimTunnel }, { HANDLERS }, { REJECTION_REASONS }, proto
] = await Promise.all([
	import('#src/server/utils/telemetry.ts'),
	import('#src/utils/logger.ts'),
	import('#src/client/utils/client-socket.ts'),
	import('#src/config/index.ts'),
	import('#src/server/create-server.ts'),
	import('#src/tests/utils.ts'),
	import('#src/utils/auth.ts'),
	import('#src/server/handlers/claimTunnel.ts'),
	import('#src/server/handlers/index.ts'),
	import('#src/utils/rejection-reason.ts'),
	import('#src/proto/api.ts')
])

class TestReader extends MetricReader {
	protected async onForceFlush() {}
	protected async onShutdown() {}
}

type Allowed = Set<string> | RegExp
const set = (...values: string[]) => new Set(values)
const ERROR_CODES = set(...Object.keys(proto.ErrorCode).filter(code => /^ERROR_/.test(code) && code !== 'ERROR_NO_ERROR'), 'INTERNAL_ERROR', 'none')
const REASONS = set(...Object.keys(REJECTION_REASONS), 'none')
const RPCS = set(...telemetry.TELEMETRY_RPC_NAMES, 'other')
const TIERS = set('authenticated', 'pre_auth')
const OUTCOMES = set('success', 'rejected', 'failure')
const ALLOWED: Record<string, Record<string, Allowed>> = {
	'attestor_rpc_requests_total': { rpc: RPCS, outcome: OUTCOMES, 'error_code': ERROR_CODES, reason: REASONS },
	'attestor_rpc_duration_seconds': { rpc: RPCS, outcome: OUTCOMES },
	'attestor_sockets_active': { tier: TIERS },
	'attestor_socket_closes_total': { tier: TIERS, 'close_code': set(...Object.values(telemetry.TELEMETRY_CLOSE_CODES), 'other') },
	'attestor_connection_terminations_total': { reason: set('INIT_TIMEOUT', 'AUTH_EXPIRED') },
	'attestor_tunnels_active': {},
	'attestor_ws_message_bytes': { tier: TIERS },
	'attestor_process_resident_memory_bytes': {},
	'attestor_nodejs_heap_used_bytes': {},
	'attestor_nodejs_heap_total_bytes': {},
	'attestor_nodejs_external_memory_bytes': {},
	'attestor_nodejs_array_buffers_bytes': {},
	'attestor_process_cpu_seconds_total': { mode: set('user', 'system') },
	'attestor_nodejs_eventloop_delay_seconds': { percentile: set('p50', 'p99', 'max') },
	'attestor_nodejs_eventloop_utilization_ratio': {},
	'attestor_build_info': {
		'upstream_commit': /^[0-9a-f]{40}$/, 'source_manifest_sha256': /^[0-9a-f]{16}$/,
		'claim_epoch': set('2'), 'claim_chain_ids': set('10143'), 'signer_address': set(SIGNER), 'node_version': set(process.version)
	}
}

const reader = new TestReader()

async function collect() {
	const { resourceMetrics, errors } = await reader.collect()
	assert.deepEqual(errors, [])
	return resourceMetrics
}

function metrics(collected: ResourceMetrics) {
	return collected.scopeMetrics.flatMap(scope => scope.metrics)
}

function points(collected: ResourceMetrics, name: string) {
	return metrics(collected).filter(metric => metric.descriptor.name === name).flatMap(metric => metric.dataPoints)
}

/** Sum of counter values, or histogram counts, over points whose attributes include `match`. */
function total(collected: ResourceMetrics, name: string, match: Record<string, string> = {}) {
	return points(collected, name)
		.filter(point => Object.entries(match).every(([key, value]) => point.attributes[key] === value))
		.reduce((sum, point) => sum + (typeof point.value === 'number' ? point.value : (point.value as { count: number }).count), 0)
}

function assertFinite(collected: ResourceMetrics) {
	const raw = JSON.stringify(collected.scopeMetrics)
	for(const value of PRIVATE_VALUES) assert.ok(!raw.includes(value), `private value reached metrics: ${value}`)
	for(const metric of metrics(collected)) {
		const allowed = ALLOWED[metric.descriptor.name]
		assert.ok(allowed, `unexpected metric ${metric.descriptor.name}`)
		for(const point of metric.dataPoints) {
			assert.deepEqual(Object.keys(point.attributes).sort(), Object.keys(allowed).sort(), metric.descriptor.name)
			for(const [key, value] of Object.entries(point.attributes)) {
				const rule = allowed[key]
				assert.ok(typeof value === 'string' && (rule instanceof RegExp ? rule.test(value) : rule.has(value)), `${metric.descriptor.name} ${key}=${String(value)}`)
			}
		}
	}
}

function captureLogs() {
	const lines: string[] = []
	const stream = new Writable({ write(chunk, _encoding, done) { lines.push(chunk.toString()); done() } })
	loggerModule.makeLogger(false, 'info', undefined, stream)
	return lines
}

async function until(condition: () => boolean | Promise<boolean>, ms: number) {
	const deadline = Date.now() + ms
	while(!await condition()) {
		assert.ok(Date.now() < deadline, `condition not met within ${ms} ms`)
		await delay(25)
	}
}

function handlerContext() {
	const tunnel = { createRequest: { host: 'example.com', port: 443, geoLocation: '', proxySessionId: '' }, transcript: [], async close() {} }
	const client = {
		authIdentity: AUTH_ID,
		authHostWhitelist: Object.freeze(['example.com']),
		metadata: { signatureType: proto.ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH, clientVersion: proto.AttestorVersion.ATTESTOR_VERSION_3_2_0 },
		assertAuthActive() {},
		getTunnel() { return tunnel },
		removeTunnel() {}
	}
	return { logger: loggerModule.logger, client } as any
}

function claimRequest(context: string) {
	return proto.ClaimTunnelRequest.create({
		request: { id: 1, host: 'example.com', port: 443 },
		data: { timestampS: claimInfo.timestampS, context }
	})
}

describe('attestor telemetry', () => {
	before(() => {
		assert.equal(telemetry.startTelemetry({ reader }), true)
	})

	it('names every RPC the server handles', () => {
		assert.deepEqual([...telemetry.TELEMETRY_RPC_NAMES].sort(), Object.keys(HANDLERS).sort())
	})

	it('stays off without an HTTP(S) metrics endpoint', () => {
		for(const endpoint of [undefined, '', '   ', 'not a url', 'ftp://collector:4319/v1/metrics']) {
			const env: NodeJS.ProcessEnv = endpoint === undefined ? {} : { OTEL_EXPORTER_OTLP_METRICS_ENDPOINT: endpoint }
			assert.equal(telemetry.startTelemetry({ env }), false, String(endpoint))
		}
	})

	it('records real init, tunnel, claim and connection outcomes with finite attributes only', async() => {
		const lines = captureLogs()
		const key = Wallet.createRandom()
		process.env.AUTHENTICATION_PUBLIC_KEY = key.publicKey
		const port = getRandomPort()
		const server = await createServer(port)
		const url = `ws://127.0.0.1:${port}${WS_PATHNAME}`
		const clients: InstanceType<typeof AttestorClient>[] = []
		let idle: WebSocket | undefined
		try {
			const start = await collect()

			const missing = new AttestorClient({ url })
			clients.push(missing)
			await assert.rejects(missing.waitForInit(), (err: any) => err.code === 'ERROR_AUTHENTICATION_FAILED')

			const auth = await createAuthRequest({ id: AUTH_ID, hostWhitelist: [canaries.host, 'example.com'] }, key.privateKey)
			const client = new AttestorClient({ url, authRequest: auth })
			clients.push(client)
			await client.waitForInit()
			await assert.rejects(client.rpc('createTunnel', { id: 7, host: canaries.tunnelHost, port: 443 }), (err: any) => err.code === 'ERROR_BAD_REQUEST')
			await assert.rejects(client.rpc('claimTunnel', { request: { id: 99, host: canaries.host, port: 443 }, data: { context: inputContext(SESSION_ID) } }), (err: any) => err.code === 'ERROR_NOT_FOUND')

			const expiring = await createAuthRequest({ id: `${AUTH_ID.slice(0, -1)}0`, hostWhitelist: ['example.com'], expiresAt: Math.floor(Date.now() / 1000) + 2 }, key.privateKey)
			const short = new AttestorClient({ url, authRequest: expiring })
			clients.push(short)
			await short.waitForInit()
			idle = new WebSocket(url)
			const idleClosed = new Promise(resolve => idle!.once('close', resolve))
			await until(async() => total(await collect(), 'attestor_connection_terminations_total', { reason: 'AUTH_EXPIRED' }) > 0, 5_000)
			await idleClosed

			await client.terminateConnection()
			await until(async() => {
				const now = await collect()
				return points(now, 'attestor_sockets_active').every(point => point.value === 0)
			}, 2_000)

			const end = await collect()
			assertFinite(end)
			const delta = (name: string, match: Record<string, string>) => total(end, name, match) - total(start, name, match)
			assert.equal(delta('attestor_rpc_requests_total', { rpc: 'init', outcome: 'failure', 'error_code': 'ERROR_AUTHENTICATION_FAILED', reason: 'AUTH_REQUIRED' }), 1)
			assert.equal(delta('attestor_rpc_requests_total', { rpc: 'init', outcome: 'success', 'error_code': 'none', reason: 'none' }), 2)
			assert.equal(delta('attestor_rpc_requests_total', { rpc: 'createTunnel', outcome: 'failure', 'error_code': 'ERROR_BAD_REQUEST', reason: 'HOST_NOT_ALLOWED' }), 1)
			assert.equal(delta('attestor_rpc_requests_total', { rpc: 'claimTunnel', outcome: 'failure', 'error_code': 'ERROR_NOT_FOUND', reason: 'TUNNEL_NOT_FOUND' }), 1)
			assert.equal(delta('attestor_rpc_duration_seconds', { rpc: 'init' }), 3)
			assert.equal(delta('attestor_connection_terminations_total', { reason: 'INIT_TIMEOUT' }), 1)
			assert.equal(delta('attestor_connection_terminations_total', { reason: 'AUTH_EXPIRED' }), 1)
			assert.equal(delta('attestor_socket_closes_total', { tier: 'pre_auth' }), 2)
			assert.equal(delta('attestor_socket_closes_total', { tier: 'authenticated' }), 2)
			assert.ok(delta('attestor_ws_message_bytes', { tier: 'authenticated' }) >= 2)

			const records = lines.map(line => JSON.parse(line) as Record<string, unknown>)
			assert.ok(records.some(record => record.stage === 'init' && record.outcome === 'success' && record.zktlsSessionId === SESSION_ID))
			assert.ok(records.every(record => record.zktlsSessionId === undefined || record.zktlsSessionId === SESSION_ID))
			const raw = lines.join('')
			for(const value of [AUTH_ID, ...HASHES, AUTH_ID.split(':').at(-1)!]) assert.ok(!raw.includes(value), 'auth binding reached a log')
		} finally {
			idle?.terminate()
			await Promise.all(clients.map(client => client.terminateConnection()))
			server.close()
			delete process.env.AUTHENTICATION_PUBLIC_KEY
		}
	})

	it('classifies claimTunnel results where the RPC is handled: signed, signed rejection, thrown', async() => {
		const signed = await claimTunnel(claimRequest(inputContext(SESSION_ID)), handlerContext())
		rejectClaim = true
		const rejected = await claimTunnel(claimRequest(inputContext(SESSION_ID)), handlerContext()).finally(() => {
			rejectClaim = false
		})
		assert.equal(rejected.error?.code, proto.ErrorCode.ERROR_INVALID_CLAIM)
		const thrown = await claimTunnel(claimRequest('{"contextAddress":"0x1"}'), handlerContext()).then(
			() => assert.fail('an unsupported context must throw'),
			(err: unknown) => err
		)
		const cases: [string, Parameters<typeof telemetry.recordRpc>[2], Record<string, string>][] = [
			['signed', { response: signed }, { outcome: 'success', 'error_code': 'none', reason: 'none' }],
			['rejected', { response: rejected }, { outcome: 'rejected', 'error_code': 'ERROR_INVALID_CLAIM', reason: 'TRANSCRIPT_DECRYPT_FAILED' }],
			['thrown', { error: thrown }, { outcome: 'failure', 'error_code': 'ERROR_BAD_REQUEST', reason: 'CLAIM_CONTEXT_INVALID' }]
		]
		for(const [name, result, match] of cases) {
			const count = async() => total(await collect(), 'attestor_rpc_requests_total', { rpc: 'claimTunnel', ...match })
			const before = await count()
			telemetry.recordRpc('claimTunnel', 3, result)
			assert.equal(await count() - before, 1, name)
		}

		assertFinite(await collect())
	})

	it('reports open tunnels, runtime and the running build', async() => {
		const source = { tunnels: { 1: {}, 2: {} } }
		telemetry.trackTunnels(source)
		try {
			assert.equal(total(await collect(), 'attestor_tunnels_active'), 2)
		} finally {
			telemetry.untrackTunnels(source)
		}

		const collected = await collect()
		assert.equal(total(collected, 'attestor_tunnels_active'), 0)
		for(const name of ['attestor_process_resident_memory_bytes', 'attestor_nodejs_heap_used_bytes', 'attestor_nodejs_array_buffers_bytes']) {
			assert.ok(total(collected, name) > 0, name)
		}

		assert.ok(total(collected, 'attestor_process_cpu_seconds_total', { mode: 'user' }) > 0)
		const manifest = readFileSync(new URL('../../umia-source-manifest.json', import.meta.url))
		const [build] = points(collected, 'attestor_build_info')
		assert.equal(build.value, 1)
		assert.deepEqual(build.attributes, {
			'upstream_commit': JSON.parse(manifest.toString('utf8')).upstreamCommit,
			'source_manifest_sha256': createHash('sha256').update(manifest).digest('hex').slice(0, 16),
			'claim_epoch': '2',
			'claim_chain_ids': '10143',
			'signer_address': SIGNER,
			'node_version': process.version
		})
		assertFinite(collected)
	})
})

describe('OTLP export', () => {
	const requests: { url?: string, headers: IncomingHttpHeaders, body: string }[] = []
	const collector = createHttpServer((req, res) => {
		let body = ''
		req.on('data', chunk => body += chunk)
		req.on('end', () => {
			requests.push({ url: req.url, headers: req.headers, body })
			res.writeHead(200, { 'Content-Type': 'application/json' }).end('{}')
		})
	})

	before(() => new Promise<void>(resolve => collector.listen(0, '127.0.0.1', resolve)))
	after(async() => {
		await telemetry.stopTelemetry()
		collector.close()
	})

	it('pushes OTLP/HTTP JSON with the attestor resource and no environment label', async() => {
		const { port } = collector.address() as AddressInfo
		assert.equal(telemetry.startTelemetry({
			env: { OTEL_EXPORTER_OTLP_METRICS_ENDPOINT: `http://127.0.0.1:${port}/v1/metrics`, OTEL_METRIC_EXPORT_INTERVAL: '200' }
		}), true)
		telemetry.recordRpc('init', 12, { response: {} })
		await until(() => requests.some(request => request.body.includes('attestor_rpc_requests_total')), 5_000)
		const request = requests.find(item => item.body.includes('attestor_rpc_requests_total'))!
		assert.equal(request.url, '/v1/metrics')
		assert.match(String(request.headers['content-type']), /^application\/json/)
		const payload = JSON.parse(request.body)
		const attributes = Object.fromEntries(payload.resourceMetrics[0].resource.attributes.map((attribute: any) => [attribute.key, attribute.value.stringValue]))
		assert.equal(attributes['service.name'], 'umia-attestor')
		assert.equal(attributes['service.namespace'], 'umia')
		assert.match(attributes['service.instance.id'], /^[0-9a-f-]{36}$/)
		assert.equal(attributes['deployment.environment'], undefined)
		assert.ok(request.body.includes('attestor_build_info'))
	})
})
