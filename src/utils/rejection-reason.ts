import type { ErrorCode } from '#src/proto/api.ts'
import { AttestorError } from '#src/utils/error.ts'

/** Finite, payload-free reasons returned in `AttestorError.data.reason` and allowed in logs: reason -> when. */
export const REJECTION_REASONS = {
	AUTH_REQUIRED: 'init or createTunnel without a verified auth request',
	AUTH_INVALID: 'auth request without data or with a signature from another key',
	AUTH_EXPIRED: 'auth expiry reached (now >= expiresAt) at init, RPC, tunnel, signing or delivery',
	HOST_LIST_INVALID: 'signed host list empty or not sorted, unique, lowercase exact hostnames',
	TUNNEL_ID_IN_USE: 'createTunnel reuses an open tunnel ID',
	TUNNEL_NOT_FOUND: 'claimTunnel, tunnel message or disconnect names no open tunnel',
	HOST_NOT_ALLOWED: 'tunnel or claim host absent from the signed host list',
	PORT_NOT_ALLOWED: 'tunnel or claim port other than 443',
	PROXY_NOT_CONFIGURED: 'geoLocation or proxySessionId requested without HTTPS_PROXY_URL',
	TUNNEL_REQUEST_MISMATCH: 'claim host, port, geoLocation or proxySessionId differs from its tunnel',
	TRANSCRIPT_MISMATCH: 'claim transcript differs from the bytes the tunnel carried',
	CLAIM_CONTEXT_INVALID: 'claim context not canonical JSON with exactly the three input keys and a lowercase address',
	CLAIM_CONTEXT_MESSAGE_UNSUPPORTED: 'contextMessage not a register, bid or wallet-bound sandbox form',
	CLAIM_CONTEXT_CHAIN_NOT_ALLOWED: 'contextMessage chain absent from CLAIM_CHAIN_IDS',
	CLAIM_CONTEXT_SESSION_MISMATCH: 'reclaimSessionId differs from the verified auth ID',
	CLAIM_REQUEST_INVALID: 'claim request without claim data',
	CLAIM_SIGNATURE_INVALID: 'claim request signature missing or not from the claim owner',
	CLAIM_TIMESTAMP_SKEW: 'claim timestamp too far in the future',
	TRANSCRIPT_DECRYPT_FAILED: 'TLS transcript handshake, reveal or ZK proof failed verification',
	TLS_HOST_MISMATCH: 'TLS server name differs from the tunnel host',
	PROVIDER_PARAMS_INVALID: 'claim parameters fail the provider schema',
	PROVIDER_VALIDATION_FAILED: 'provider unknown, or it rejected the decrypted request or response',
	SIGNED_CONTEXT_INVALID: 'derived context or extracted parameters fail the before-sign policy',
	CLAIM_PROVIDER_UNSUPPORTED: 'claim provider other than http',
	CLAIM_PARAMS_INVALID: 'claim parameters not canonical JSON with a string url',
	CLAIM_URL_MISMATCH: 'claim URL not canonical HTTPS on port 443 at the tunnel host',
	TEE_CLAIMS_DISABLED: 'claimTeeBundle, disabled until TEE outputs bind the endpoint',
	AUTH_LIFETIME_INVALID: 'auth createdAt over 60 s ahead, or expiresAt not within 15 min after createdAt',
	INIT_TIMEOUT: 'socket not initialised within 5 s of connecting',
	CERTIFICATE_FETCH_DISABLED: 'fetchCertificateBytes or an AIA issuer fetch, disabled: the URL is client-chosen',
	TOPRF_DISABLED: 'toprf RPC, disabled: Umia recipes use oprf-raw inside claimTunnel',
	AUTH_SOCKET_LIMIT: 'init while MAX_SOCKETS_PER_AUTH sockets on this instance hold the same auth ID',
	CERTIFICATE_DISTRUSTED: 'provider TLS chain uses a compromised eMudhra CA key (October 2026) or is issued under emSign ECC Root CA - G3 or AAA Certificate Services'
} as const
export type RejectionReason = keyof typeof REJECTION_REASONS

export function rejection(code: keyof typeof ErrorCode, reason: RejectionReason, message: string) {
	return new AttestorError(code, message, { reason })
}

export function rejectionReason(err: unknown): RejectionReason | undefined {
	if(!(err instanceof AttestorError)) return undefined
	const reason: unknown = err.data?.reason
	return typeof reason === 'string' && Object.hasOwn(REJECTION_REASONS, reason)
		? reason as RejectionReason
		: undefined
}

/** Labels an upstream failure once; the innermost reason wins. */
export function withRejectionReason(
	err: unknown,
	reason: RejectionReason,
	fallbackCode: keyof typeof ErrorCode = 'ERROR_INVALID_CLAIM'
) {
	const base = AttestorError.fromError(err as Error, fallbackCode)
	if(rejectionReason(base)) return base
	return new AttestorError(base.code, base.message, { ...base.data, reason })
}
