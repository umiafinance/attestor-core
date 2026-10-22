import { createHash, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { type EventLoopUtilization, monitorEventLoopDelay, performance } from 'node:perf_hooks'

import type { Attributes, Counter, Histogram, ObservableGauge } from '@opentelemetry/api'
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http'
import { resourceFromAttributes } from '@opentelemetry/resources'
import { MeterProvider, type MetricReader, PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics'
import type { WebSocket } from 'ws'

import { CLAIM_CHAIN_IDS } from '#src/config/claim-chain-ids.ts'
import { CLAIM_EPOCH } from '#src/config/claim-epoch.ts'
import { getAttestorAddress } from '#src/server/utils/generics.ts'
import { AttestorError } from '#src/utils/error.ts'
import { safeErrorCode } from '#src/utils/logger.ts'
import { rejectionReason } from '#src/utils/rejection-reason.ts'
import { SelectedServiceSignatureType } from '#src/utils/signatures/index.ts'

/** Every RPC the server handles; anything else is counted as `other`. */
export const TELEMETRY_RPC_NAMES = [
	'init', 'createTunnel', 'disconnectTunnel', 'claimTunnel', 'claimTeeBundle', 'toprf',
	'fetchCertificateBytes', 'createClaimOnChain', 'completeClaimOnChain', 'createTaskOnMechain'
] as const

export type SocketTier = 'authenticated' | 'pre_auth'
export type TerminationReason = 'INIT_TIMEOUT' | 'AUTH_EXPIRED'
/** A handled RPC's response, or what it threw. */
export type RpcResult = { response: unknown } | { error: unknown }

export const TELEMETRY_CLOSE_CODES: Readonly<Record<number, string>> = {
	1000: 'normal', 1001: 'going_away', 1002: 'protocol_error', 1003: 'unsupported_data',
	1005: 'no_status', 1006: 'abnormal', 1007: 'invalid_payload', 1008: 'policy_violation',
	1009: 'message_too_big', 1011: 'internal_error'
}

const DURATION_BUCKETS_S = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 60, 90, 120]
const MESSAGE_BUCKETS_BYTES = [1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 33554432]
const DEFAULT_EXPORT_INTERVAL_MS = 30_000
const MAX_EXPORT_TIMEOUT_MS = 10_000
const ADDRESS = /^0x[0-9a-f]{40}$/
const COMMIT = /^[0-9a-f]{40}$/

type Instruments = {
	provider: MeterProvider
	rpcRequests: Counter
	rpcDuration: Histogram
	socketCloses: Counter
	terminations: Counter
	messageBytes: Histogram
	eventLoopDelay: ReturnType<typeof monitorEventLoopDelay>
}

let instruments: Instruments | undefined
let buildInfo: Attributes | undefined
const openSockets: Record<SocketTier, number> = { authenticated: 0, pre_auth: 0 }
const tunnelSources = new Set<{ tunnels: object }>()

/**
 * Starts metric export when OTEL_EXPORTER_OTLP_METRICS_ENDPOINT names an HTTP(S)
 * URL, or records into `reader` for tests. Returns whether metrics are recorded.
 */
export function startTelemetry(
	{ env = process.env, reader }: { env?: NodeJS.ProcessEnv, reader?: MetricReader } = {}
) {
	try {
		const metricReader = reader ?? exportingReader(env)
		if(!metricReader) return false
		void stopTelemetry()
		const provider = new MeterProvider({
			resource: resourceFromAttributes({
				'service.name': env.OTEL_SERVICE_NAME?.trim() || 'umia-attestor',
				'service.namespace': 'umia',
				'service.instance.id': randomUUID()
			}),
			readers: [metricReader]
		})
		instruments = createInstruments(provider)
		return true
	} catch {
		return false
	}
}

export async function stopTelemetry() {
	const current = instruments
	instruments = undefined
	if(!current) return
	current.eventLoopDelay.disable()
	await current.provider.shutdown().catch(() => {})
}

/**
 * Counts one handled RPC. A response that carries a signed error instead of a result, such as
 * a claimTunnel rejection, is `rejected`; a thrown error is `failure`.
 */
export function recordRpc(type: unknown, durationMs: number, result: RpcResult) {
	record(({ rpcRequests, rpcDuration }) => {
		const error = 'error' in result ? result.error : signedError(result.response)
		const outcome = 'error' in result ? 'failure' : error ? 'rejected' : 'success'
		const rpc = rpcName(type)
		rpcRequests.add(1, {
			rpc,
			outcome,
			error_code: error ? safeErrorCode(error) : 'none',
			reason: error ? rejectionReason(error) ?? 'none' : 'none'
		})
		rpcDuration.record(Math.max(0, durationMs) / 1000, { rpc, outcome })
	})
}

export function recordTermination(reason: TerminationReason) {
	record(({ terminations }) => terminations.add(1, { reason }))
}

/** Counts the socket in its admission tier until it closes, with its inbound message sizes. */
export function observeSocket(ws: WebSocket, tier: SocketTier) {
	safely(() => {
		openSockets[tier] += 1
		ws.on('message', data => record(({ messageBytes }) => {
			const bytes = byteLength(data)
			if(bytes !== undefined) messageBytes.record(bytes, { tier })
		}))
		ws.once('close', code => {
			openSockets[tier] = Math.max(0, openSockets[tier] - 1)
			record(({ socketCloses }) => socketCloses.add(1, { tier, close_code: closeCodeName(code) }))
		})
	})
}

export function trackTunnels(source: { tunnels: object }) {
	tunnelSources.add(source)
}

export function untrackTunnels(source: { tunnels: object }) {
	tunnelSources.delete(source)
}

function exportingReader(env: NodeJS.ProcessEnv) {
	const url = env.OTEL_EXPORTER_OTLP_METRICS_ENDPOINT?.trim()
	if(!url || !URL.canParse(url) || !['http:', 'https:'].includes(new URL(url).protocol)) return undefined
	const requested = Number(env.OTEL_METRIC_EXPORT_INTERVAL)
	const interval = Number.isSafeInteger(requested) && requested >= 100 && requested <= 3_600_000
		? requested
		: DEFAULT_EXPORT_INTERVAL_MS
	const timeout = Math.min(MAX_EXPORT_TIMEOUT_MS, interval)
	return new PeriodicExportingMetricReader({
		exporter: new OTLPMetricExporter({ url, timeoutMillis: timeout }),
		exportIntervalMillis: interval,
		exportTimeoutMillis: timeout
	})
}

function createInstruments(provider: MeterProvider): Instruments {
	const meter = provider.getMeter('umia-attestor')
	const gauge = (name: string, description: string, unit?: string) => meter.createObservableGauge(name, { description, unit })
	const socketsActive = gauge('attestor_sockets_active', 'Open WebSocket connections by admission tier')
	const tunnelsActive = gauge('attestor_tunnels_active', 'Open provider tunnels across connections')
	const residentMemory = gauge('attestor_process_resident_memory_bytes', 'Process resident set size', 'By')
	const heapUsed = gauge('attestor_nodejs_heap_used_bytes', 'V8 heap in use', 'By')
	const heapTotal = gauge('attestor_nodejs_heap_total_bytes', 'V8 heap reserved', 'By')
	const externalMemory = gauge('attestor_nodejs_external_memory_bytes', 'Memory of C++ objects bound to JavaScript', 'By')
	const arrayBuffers = gauge('attestor_nodejs_array_buffers_bytes', 'ArrayBuffer and Buffer memory', 'By')
	const eventLoopDelaySeconds = gauge('attestor_nodejs_eventloop_delay_seconds', 'Event loop delay since the previous collection', 's')
	const eventLoopUtilization = gauge('attestor_nodejs_eventloop_utilization_ratio', 'Event loop utilization since the previous collection', '1')
	const build = gauge('attestor_build_info', 'Running source, epoch, chains and signer; always 1')
	const cpu = meter.createObservableCounter('attestor_process_cpu_seconds_total', { description: 'Process CPU time', unit: 's' })
	const eventLoopDelay = monitorEventLoopDelay({ resolution: 20 })
	eventLoopDelay.enable()
	let lastUtilization: EventLoopUtilization = performance.eventLoopUtilization()

	const observed: ObservableGauge[] = [
		socketsActive, tunnelsActive, residentMemory, heapUsed, heapTotal, externalMemory,
		arrayBuffers, eventLoopDelaySeconds, eventLoopUtilization, build
	]
	meter.addBatchObservableCallback(result => safely(() => {
		result.observe(socketsActive, openSockets.authenticated, { tier: 'authenticated' })
		result.observe(socketsActive, openSockets.pre_auth, { tier: 'pre_auth' })
		let tunnels = 0
		for(const source of tunnelSources) tunnels += Object.keys(source.tunnels).length
		result.observe(tunnelsActive, tunnels)
		const memory = process.memoryUsage()
		result.observe(residentMemory, memory.rss)
		result.observe(heapUsed, memory.heapUsed)
		result.observe(heapTotal, memory.heapTotal)
		result.observe(externalMemory, memory.external)
		result.observe(arrayBuffers, memory.arrayBuffers)
		const usage = process.cpuUsage()
		result.observe(cpu, usage.user / 1e6, { mode: 'user' })
		result.observe(cpu, usage.system / 1e6, { mode: 'system' })
		if(eventLoopDelay.count > 0) {
			result.observe(eventLoopDelaySeconds, eventLoopDelay.percentile(50) / 1e9, { percentile: 'p50' })
			result.observe(eventLoopDelaySeconds, eventLoopDelay.percentile(99) / 1e9, { percentile: 'p99' })
			result.observe(eventLoopDelaySeconds, eventLoopDelay.max / 1e9, { percentile: 'max' })
		}

		eventLoopDelay.reset()
		const utilization = performance.eventLoopUtilization()
		result.observe(eventLoopUtilization, performance.eventLoopUtilization(utilization, lastUtilization).utilization)
		lastUtilization = utilization
		result.observe(build, 1, getBuildInfo())
	}), [...observed, cpu])

	return {
		provider,
		rpcRequests: meter.createCounter('attestor_rpc_requests_total', {
			description: 'RPC requests by RPC, outcome, error code and rejection reason'
		}),
		rpcDuration: meter.createHistogram('attestor_rpc_duration_seconds', {
			description: 'RPC handling time by RPC and outcome',
			unit: 's',
			advice: { explicitBucketBoundaries: DURATION_BUCKETS_S }
		}),
		socketCloses: meter.createCounter('attestor_socket_closes_total', {
			description: 'Closed WebSocket connections by admission tier and close code'
		}),
		terminations: meter.createCounter('attestor_connection_terminations_total', {
			description: 'Connections the server ended for a missed init or an expired auth'
		}),
		messageBytes: meter.createHistogram('attestor_ws_message_bytes', {
			description: 'Inbound WebSocket message size by admission tier',
			unit: 'By',
			advice: { explicitBucketBoundaries: MESSAGE_BUCKETS_BYTES }
		}),
		eventLoopDelay
	}
}

/** Runs `fn` while metrics are recorded. */
function record(fn: (current: Instruments) => void) {
	const current = instruments
	if(current) safely(() => fn(current))
}

function safely(fn: () => void) {
	try {
		fn()
	} catch {
		// Telemetry must not change the result of an attestor operation.
	}
}

/** The signed error a handled RPC returned in place of its result. */
function signedError(response: unknown) {
	const error = (response as { error?: Parameters<typeof AttestorError.fromProto>[0] } | undefined)?.error
	return error ? AttestorError.fromProto(error) : undefined
}

function closeCodeName(code: unknown) {
	return typeof code === 'number' && Object.hasOwn(TELEMETRY_CLOSE_CODES, code) ? TELEMETRY_CLOSE_CODES[code] : 'other'
}

function rpcName(type: unknown): string {
	return typeof type === 'string' && (TELEMETRY_RPC_NAMES as readonly string[]).includes(type) ? type : 'other'
}

function byteLength(data: unknown): number | undefined {
	if(Array.isArray(data)) return data.reduce((total: number, part: unknown) => total + (byteLength(part) ?? 0), 0)
	if(data instanceof ArrayBuffer || ArrayBuffer.isView(data)) return data.byteLength
	return undefined
}

function getBuildInfo(): Attributes {
	if(buildInfo) return buildInfo
	let upstreamCommit = 'unknown'
	let sourceManifest = 'unknown'
	try {
		// The builder writes the source manifest at the package root, beside src/.
		const raw = readFileSync(new URL('../../../umia-source-manifest.json', import.meta.url))
		sourceManifest = createHash('sha256').update(raw).digest('hex').slice(0, 16)
		const commit: unknown = JSON.parse(raw.toString('utf8'))?.upstreamCommit
		if(typeof commit === 'string' && COMMIT.test(commit)) upstreamCommit = commit
	} catch {
		// A source tree without the builder's manifest reports `unknown`.
	}

	let signer = 'unknown'
	try {
		const address = getAttestorAddress(SelectedServiceSignatureType).toLowerCase()
		if(ADDRESS.test(address)) signer = address
	} catch {
		// The signer is reported only when the configured key derives an address.
	}

	buildInfo = {
		upstream_commit: upstreamCommit,
		source_manifest_sha256: sourceManifest,
		claim_epoch: String(CLAIM_EPOCH),
		claim_chain_ids: CLAIM_CHAIN_IDS.join(','),
		signer_address: signer,
		node_version: process.version
	}
	return buildInfo
}
