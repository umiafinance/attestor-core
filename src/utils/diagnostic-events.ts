/** Server-owned event references keep classification independent of log wording. */
export const BGP_EVENTS = {
	connecting: { stage: 'bgp', outcome: 'started' },
	reconnecting: { stage: 'bgp', outcome: 'started' },
	connected: { stage: 'bgp', outcome: 'success' },
	update: { stage: 'bgp', outcome: 'success' },
	connectFailed: { stage: 'bgp', outcome: 'failure', reason: 'BGP_CONNECT_FAILED' },
	subscribeFailed: { stage: 'bgp', outcome: 'failure', reason: 'BGP_SUBSCRIBE_FAILED' },
	notOpen: { stage: 'bgp', outcome: 'failure', reason: 'BGP_NOT_OPEN' },
	connectionError: { stage: 'bgp', outcome: 'failure', reason: 'BGP_CONNECTION_ERROR' },
	closed: { stage: 'bgp', outcome: 'failure', reason: 'BGP_CLOSED' },
	closeFailed: { stage: 'bgp', outcome: 'failure', reason: 'BGP_CLOSE_FAILED' },
	messageInvalid: { stage: 'bgp', outcome: 'failure', reason: 'BGP_MESSAGE_INVALID' }
} as const

const ERROR_REASONS = {
	InvalidStateError: 'INVALID_STATE',
	ECONNRESET: 'CONNECTION_RESET',
	EPIPE: 'BROKEN_PIPE',
	ECONNREFUSED: 'CONNECTION_REFUSED',
	ETIMEDOUT: 'CONNECTION_TIMEOUT',
	UND_ERR_CONNECT_TIMEOUT: 'CONNECTION_TIMEOUT',
	ENOTFOUND: 'DNS_LOOKUP_FAILED',
	EAI_AGAIN: 'DNS_LOOKUP_FAILED',
	ENETUNREACH: 'NETWORK_UNREACHABLE',
	EHOSTUNREACH: 'NETWORK_UNREACHABLE'
} as const

export type DiagnosticEvent = typeof BGP_EVENTS[keyof typeof BGP_EVENTS]
export type DiagnosticReason = Extract<DiagnosticEvent, { reason: string }>['reason']
	| typeof ERROR_REASONS[keyof typeof ERROR_REASONS]

// Capture immutable projections; client-shaped copies cannot become trusted events.
const events = new Map<unknown, DiagnosticEvent>(Object.values(BGP_EVENTS)
	.map(event => [event, Object.freeze({ ...event })] as const))
const reasons = new Set<string>([
	...Object.values(ERROR_REASONS),
	...Object.values(BGP_EVENTS).flatMap(event => 'reason' in event ? [event.reason] : [])
])

export function diagnosticEvent(value: unknown): DiagnosticEvent | undefined {
	return events.get(value)
}

export function isDiagnosticReason(value: unknown): value is DiagnosticReason {
	return typeof value === 'string' && reasons.has(value)
}

export function diagnosticReason(err: unknown): DiagnosticReason | undefined {
	if(!(err instanceof Error)) return undefined
	const code = err.name === 'InvalidStateError' ? err.name : (err as NodeJS.ErrnoException).code
	return typeof code === 'string' && Object.hasOwn(ERROR_REASONS, code)
		? ERROR_REASONS[code as keyof typeof ERROR_REASONS]
		: undefined
}
