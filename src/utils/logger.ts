import { type Bindings, type ChildLoggerOptions, type DestinationStream, type Logger as PinoLogger, type LoggerOptions, pino, stdTimeFunctions } from 'pino'

import type { LogLevel } from '#src/types/index.ts'
import { ErrorCode } from '#src/proto/api.ts'
import { getEnvVariable } from '#src/utils/env.ts'
import { AttestorError } from '#src/utils/error.ts'
import { REJECTION_REASONS, type RejectionReason, rejectionReason } from '#src/utils/rejection-reason.ts'

const STAGES = ['connection', 'init', 'rpc', 'tunnel', 'claimTunnel', 'claimTeeBundle', 'provider', 'tee'] as const
const OUTCOMES = ['started', 'success', 'failure', 'timeout', 'expired'] as const
const HANDLERS = ['claimTunnel', 'claimTeeBundle'] as const
type Stage = typeof STAGES[number]
type Outcome = typeof OUTCOMES[number]
type Handler = typeof HANDLERS[number]
type SafeErrorCode = keyof typeof ErrorCode | 'INTERNAL_ERROR'
type SafeEvidence = { durationMs?: number, errorCode?: SafeErrorCode, reason?: RejectionReason }
const EVENTS: Record<string, { stage: Stage, outcome: Outcome, errorCode?: SafeErrorCode }> = {
	'new connection, validating...': { stage: 'connection', outcome: 'started' },
	'connection accepted': { stage: 'connection', outcome: 'success' },
	'error in new connection': { stage: 'init', outcome: 'failure' },
	'auth session established': { stage: 'init', outcome: 'success' },
	'auth expired': { stage: 'init', outcome: 'expired', errorCode: 'ERROR_AUTHENTICATION_FAILED' },
	'handling RPC request': { stage: 'rpc', outcome: 'started' },
	'handled RPC request': { stage: 'rpc', outcome: 'success' },
	'error in RPC request': { stage: 'rpc', outcome: 'failure' },
	'RPC took too long to respond': { stage: 'rpc', outcome: 'timeout' },
	'failed to deliver RPC error response': { stage: 'rpc', outcome: 'failure' },
	'error processing message': { stage: 'rpc', outcome: 'failure' },
	'error writing to tunnel': { stage: 'tunnel', outcome: 'failure' },
	'failed to forward tunnel message': { stage: 'tunnel', outcome: 'failure' },
	'failed to send tunnel disconnect event': { stage: 'tunnel', outcome: 'failure' },
	'error closing tunnel': { stage: 'tunnel', outcome: 'failure' },
	'invalid claim request': { stage: 'claimTunnel', outcome: 'failure' },
	'claim tunnel rejected': { stage: 'claimTunnel', outcome: 'failure' },
	'claim tunnel completed': { stage: 'claimTunnel', outcome: 'success' },
	'Starting TEE bundle verification': { stage: 'claimTeeBundle', outcome: 'started' },
	'TEE bundle claim validation successful': { stage: 'claimTeeBundle', outcome: 'success' },
	'TEE bundle claim processing completed': { stage: 'claimTeeBundle', outcome: 'success' },
	'TEE provider validation completed successfully': { stage: 'provider', outcome: 'success' },
	'initialised APM agent': { stage: 'connection', outcome: 'success' },
	'APM configuration rejected': { stage: 'connection', outcome: 'failure' }
}
const MAX_DURATION_MS = 86_400_000
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const SESSION_ID = /^[A-Za-z0-9_:-]{1,128}$/
const serverRefs = new WeakSet<object>()
const sessionRefs = new WeakSet<object>()

export function createServerLogRef(generate: () => string): Readonly<{ value: string }> | undefined {
	// Server callers supply the Node CSPRNG; failed logging correlation is optional.
	try {
		const value = generate()
		if(!UUID_V4.test(value)) return undefined
		const ref = Object.freeze({ value })
		serverRefs.add(ref)
		return ref
	} catch {
		return undefined
	}
}

/** Call only with the ID of a verified auth request: the Umia zkTLS session ID that other hops log. */
export function createVerifiedSessionRef(id: string): Readonly<{ value: string }> | undefined {
	if(!SESSION_ID.test(id)) return undefined
	const ref = Object.freeze({ value: id })
	sessionRefs.add(ref)
	return ref
}

export function safeRpcStage(type: unknown): Stage {
	if(type === 'init') return 'init'
	if(type === 'createTunnel' || type === 'disconnectTunnel') return 'tunnel'
	if(type === 'claimTunnel' || type === 'claimTeeBundle') return type
	return 'rpc'
}

export function safeHandler(type: unknown): Handler | undefined {
	return type === 'claimTunnel' || type === 'claimTeeBundle' ? type : undefined
}

export function safeErrorCode(error: unknown): SafeErrorCode {
	return error instanceof AttestorError && error.code !== 'ERROR_NO_ERROR' && Object.hasOwn(ErrorCode, error.code)
		? error.code
		: 'INTERNAL_ERROR'
}

const envLevel = getEnvVariable('LOG_LEVEL') as LogLevel
export let logger: PinoLogger
makeLogger(false, envLevel)

// Client data and nested errors reach both log calls and child bindings.
export function makeLogger(
	redactPii: boolean,
	level?: LogLevel,
	onLog?: (level: LogLevel, log: any) => void,
	stream?: DestinationStream
) {
	const opts: LoggerOptions = {
		timestamp: stdTimeFunctions.isoTime,
		formatters: {
			bindings(bindings) {
				return projectContext(bindings)
			},
			log: redact
		},
		hooks: {
			logMethod(args, method, levelNumber) {
				try {
					const message = args.find(arg => typeof arg === 'string')
					const details = args.find(arg => typeof arg === 'object' && arg !== null)
					const evidence = projectEvidence(details)
					const event: { stage: Stage, outcome: Outcome, errorCode?: SafeErrorCode } = typeof message === 'string' && Object.hasOwn(EVENTS, message)
						? EVENTS[message]
						: { stage: 'rpc', outcome: evidence.errorCode || levelNumber >= 40 ? 'failure' : 'started' }
					if(event.outcome === 'success' || event.outcome === 'started') {
						delete evidence.errorCode
						delete evidence.reason
					}
					method.apply(this, [{ ...evidence, ...event }, 'attestor diagnostic'])
				} catch {
					// Logging must not change the result of an attestor operation.
				}
			}
		}
	}
	if(redactPii) {
		opts.browser = {
			write: {
				fatal: log => writeLog('fatal', log),
				error: log => writeLog('error', log),
				warn: log => writeLog('warn', log),
				info: log => writeLog('info', log),
				debug: log => writeLog('debug', log),
				trace: log => writeLog('trace', log)
			}
		}
	}
	const pLogger = hardenChildren(stream ? pino(opts, stream) : pino(opts))
	pLogger.level = level || 'info'
	logger = pLogger
	return pLogger

	function writeLog(logLevel: LogLevel, log: any) {
		const safe = redact(log)
		if(console[logLevel]) console[logLevel](safe, 'attestor diagnostic')
		else console.log(safe, 'attestor diagnostic')
		onLog?.(logLevel, { ...safe, msg: 'attestor diagnostic' })
	}
}

function hardenChildren(
	target: PinoLogger,
	inherited: Record<string, unknown> = {},
	createChild: PinoLogger['child'] = target.child
): PinoLogger {
	target.child = ((bindings: Bindings, options?: ChildLoggerOptions) => {
		const safe = { ...inherited, ...safeChildBindings(bindings) }
		return hardenChildren(createChild.call(target, projectContext(safeChildBindings(bindings)), options), safe, createChild)
	}) as PinoLogger['child']
	return target
}

function safeChildBindings(input: unknown): Record<string, unknown> {
	if(!input || typeof input !== 'object') {
		return {}
	}
	try {
		const value = input as Record<string, unknown>
		const safe: Record<string, unknown> = {}
		if(typeof value.handler === 'string' && HANDLERS.includes(value.handler as Handler)) {
			safe.handler = value.handler
		}
		// Keep branded refs opaque until Pino's binding formatter projects them.
		if(value.connectionRef && typeof value.connectionRef === 'object' && serverRefs.has(value.connectionRef)) {
			safe.connectionRef = value.connectionRef
		}
		if(value.operationRef && typeof value.operationRef === 'object' && serverRefs.has(value.operationRef)) {
			safe.operationRef = value.operationRef
		}
		if(value.zktlsSessionId && typeof value.zktlsSessionId === 'object' && sessionRefs.has(value.zktlsSessionId)) {
			safe.zktlsSessionId = value.zktlsSessionId
		}
		return safe
	} catch {
		return {}
	}
}

function projectContext(input: unknown): Record<string, unknown> {
	if(!input || typeof input !== 'object') return {}
	try {
		const value = input as Record<string, unknown>
		const safe: Record<string, unknown> = {}
		if(typeof value.handler === 'string' && HANDLERS.includes(value.handler as Handler)) safe.handler = value.handler
		if(value.connectionRef && typeof value.connectionRef === 'object' && serverRefs.has(value.connectionRef)) safe.connectionRef = (value.connectionRef as { value: string }).value
		if(value.operationRef && typeof value.operationRef === 'object' && serverRefs.has(value.operationRef)) safe.operationRef = (value.operationRef as { value: string }).value
		if(value.zktlsSessionId && typeof value.zktlsSessionId === 'object' && sessionRefs.has(value.zktlsSessionId)) safe.zktlsSessionId = (value.zktlsSessionId as { value: string }).value
		return safe
	} catch {
		return {}
	}
}


function projectEvidence(input: unknown): SafeEvidence {
	if(input instanceof Error) return errorEvidence(input)
	if(!input || typeof input !== 'object') return {}
	try {
		const value = input as Record<string, unknown>
		const safe: SafeEvidence = {}
		if(typeof value.durationMs === 'number' && Number.isSafeInteger(value.durationMs) && value.durationMs >= 0 && value.durationMs <= MAX_DURATION_MS) safe.durationMs = value.durationMs
		const err = value.err ?? value.error
		if(err !== undefined) Object.assign(safe, errorEvidence(err))
		return safe
	} catch {
		return {}
	}
}

function errorEvidence(err: unknown): SafeEvidence {
	const reason = rejectionReason(err)
	return reason ? { errorCode: safeErrorCode(err), reason } : { errorCode: safeErrorCode(err) }
}

export function redact(input: unknown): Record<string, unknown> {
	if(!input || typeof input !== 'object') return {}
	try {
		const value = input as Record<string, unknown>
		const safe: Record<string, unknown> = { ...projectContext(input), ...projectEvidence(input) }
		if(typeof value.stage === 'string' && STAGES.includes(value.stage as Stage)) safe.stage = value.stage
		if(typeof value.outcome === 'string' && OUTCOMES.includes(value.outcome as Outcome)) safe.outcome = value.outcome
		if(typeof value.errorCode === 'string' && (value.errorCode === 'INTERNAL_ERROR' || Object.hasOwn(ErrorCode, value.errorCode))) safe.errorCode = value.errorCode
		if(typeof value.reason === 'string' && Object.hasOwn(REJECTION_REASONS, value.reason)) safe.reason = value.reason
		return safe
	} catch {
		return {}
	}
}
