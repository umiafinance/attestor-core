import { createHash } from 'node:crypto'

import { CHAIN_ID } from '#src/utils/chain-id.ts'
import { canonicalStringify } from '#src/utils/claims.ts'
import { AttestorError } from '#src/utils/error.ts'
import type { RejectionReason } from '#src/utils/rejection-reason.ts'

const INPUT_KEYS = ['contextAddress', 'contextMessage', 'identityProvider', 'reclaimSessionId']
const SIGNED_KEYS = [...INPUT_KEYS, 'providerHash', 'extractedParameters']
const RESERVED_EXTRACTED_KEYS = new Set([...SIGNED_KEYS, 'attestationNonce', 'attestationNonceData'])
const ADDRESS = /^0x[a-f0-9]{40}$/
const HASH = /^0x[a-f0-9]{64}$/
const IDENTITY_PROVIDER = /^[a-z][a-z0-9_]{0,63}$/
const DECIMAL = /^(0|[1-9][0-9]*)$/
const MESSAGE = /^[\x20-\x21\x23-\x5b\x5d-\x7e]+$/
const EXTRACTED_KEY = /^[a-z][a-z0-9_]{0,63}$/
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

type InputContext = {
	contextAddress: string
	contextMessage: string
	identityProvider: string
	reclaimSessionId: string
	allowedHashes: readonly string[]
	chainId: string
}

function boundAuthIdentity(value: string | undefined): {
	sessionId: string, identityProvider: string, allowedHashes: string[], scopeDigest: string
} | undefined {
	if(!value) return undefined
	const parts = value.split(':')
	if(parts.length !== 5 || parts[0] !== 'umia1' || !parts[1]
		|| !IDENTITY_PROVIDER.test(parts[2]) || !/^[a-f0-9]{64}$/.test(parts[4])) return undefined
	const hashes = parts[3].split(',')
	if(!hashes.length || hashes.some(hash => !HASH.test(hash))
		|| [...hashes].sort().join(',') !== parts[3]
		|| new Set(hashes).size !== hashes.length) return undefined
	return { sessionId: parts[1], identityProvider: parts[2], allowedHashes: hashes, scopeDigest: parts[4] }
}

/** The Umia session ID inside a `umia1:` auth ID; the hops correlate their logs on it. */
export function boundAuthSessionId(authIdentity: string | undefined): string | undefined {
	return boundAuthIdentity(authIdentity)?.sessionId
}

// The runner adapter matches this exact message; the reason carries the finite detail.
function invalid(reason: RejectionReason): never {
	throw AttestorError.badRequest('Unsupported claim context', { reason })
}

function parseCanonicalObject(raw: unknown, keys: readonly string[], reason: RejectionReason): Record<string, unknown> {
	if(typeof raw !== 'string') return invalid(reason)
	let value: unknown
	try {
		value = JSON.parse(raw)
	} catch {
		return invalid(reason)
	}
	if(!value || typeof value !== 'object' || Array.isArray(value)) return invalid(reason)
	const context = value as Record<string, unknown>
	const actualKeys = Object.keys(context)
	if(actualKeys.length !== keys.length || actualKeys.some(key => !keys.includes(key))) return invalid(reason)
	// A canonical byte comparison also rejects duplicate raw JSON keys before signing.
	if(canonicalStringify(context) !== raw) return invalid(reason)
	return context
}

type ContextMessageForm = { kind: 'register' | 'bid' | 'sandbox', chainId: string }

/** Parses the three accepted message forms before the instance's chain scope applies. */
function parseContextMessage(value: unknown, contextAddress: string): ContextMessageForm | undefined {
	if(typeof value !== 'string' || !MESSAGE.test(value)) return undefined
	const [kind, chainId = '', address = '', ...rest] = value.split(':')
	if(!CHAIN_ID.test(chainId) || !ADDRESS.test(address)) return undefined
	if(kind === 'register' && rest.length === 1 && rest[0]) return { kind, chainId }
	if(kind === 'bid' && rest.length === 3
		&& DECIMAL.test(rest[0]) && DECIMAL.test(rest[1]) && rest[2]) return { kind, chainId }
	// Generation-only sandbox challenge bound to the session wallet. The hook only accepts
	// register:/bid: prefixes, so a sandbox claim can never satisfy an auction.
	if(kind === 'sandbox' && rest.length === 1
		&& address === contextAddress && UUID_V4.test(rest[0])) return { kind, chainId }
	return undefined
}

export function assertSupportedInputContext(
	raw: unknown,
	authIdentity: string | undefined,
	chainIds: readonly string[]
): InputContext {
	const input = parseCanonicalObject(raw, INPUT_KEYS, 'CLAIM_CONTEXT_INVALID')
	if(typeof input.contextAddress !== 'string' || !ADDRESS.test(input.contextAddress)) {
		return invalid('CLAIM_CONTEXT_INVALID')
	}
	if(typeof input.identityProvider !== 'string' || !IDENTITY_PROVIDER.test(input.identityProvider)) {
		return invalid('CLAIM_CONTEXT_INVALID')
	}
	const form = parseContextMessage(input.contextMessage, input.contextAddress)
	if(!form) return invalid('CLAIM_CONTEXT_MESSAGE_UNSUPPORTED')
	if(!chainIds.includes(form.chainId)) return invalid('CLAIM_CONTEXT_CHAIN_NOT_ALLOWED')
	const binding = boundAuthIdentity(authIdentity)
	if(!binding || input.reclaimSessionId !== binding.sessionId
		|| input.identityProvider !== binding.identityProvider) return invalid('CLAIM_CONTEXT_SESSION_MISMATCH')
	const messageDigest = `sha256:${createHash('sha256').update(input.contextMessage as string).digest('hex')}`
	const scopeDigest = createHash('sha256')
		.update(`${input.contextAddress}:${messageDigest}`).digest('hex')
	if(scopeDigest !== binding.scopeDigest) return invalid('CLAIM_CONTEXT_SESSION_MISMATCH')
	return {
		contextAddress: input.contextAddress,
		contextMessage: input.contextMessage as string,
		identityProvider: input.identityProvider,
		reclaimSessionId: binding.sessionId,
		allowedHashes: binding.allowedHashes,
		chainId: form.chainId
	}
}

export function assertSupportedSignedContext(raw: unknown, input: InputContext): void {
	if(typeof raw !== 'string') return invalid('SIGNED_CONTEXT_INVALID')
	const signed = parseCanonicalObject(raw, SIGNED_KEYS, 'SIGNED_CONTEXT_INVALID')
	for(const key of INPUT_KEYS) {
		if(signed[key] !== input[key]) return invalid('SIGNED_CONTEXT_INVALID')
	}
	if(typeof signed.providerHash !== 'string' || !HASH.test(signed.providerHash)) return invalid('SIGNED_CONTEXT_INVALID')
	if(!input.allowedHashes.includes(signed.providerHash)) return invalid('SIGNED_CONTEXT_INVALID')
	const extracted = signed.extractedParameters
	if(!extracted || typeof extracted !== 'object' || Array.isArray(extracted)) return invalid('SIGNED_CONTEXT_INVALID')
	const entries = Object.entries(extracted)
	if(!entries.length || entries.some(([key, value]) =>
		!EXTRACTED_KEY.test(key) || RESERVED_EXTRACTED_KEYS.has(key)
		|| typeof value !== 'string' || !value.trim().length)) return invalid('SIGNED_CONTEXT_INVALID')

	// Claims.sol reads the first raw target, so each must identify this top-level value.
	for(const key of ['contextAddress', 'contextMessage', 'identityProvider', 'providerHash'] as const) {
		const target = `"${key}":"`
		if(raw.indexOf(target) !== raw.lastIndexOf(target)) return invalid('SIGNED_CONTEXT_INVALID')
		const start = raw.indexOf(target) + target.length
		if(start < target.length || raw.slice(start, raw.indexOf('"', start)) !== signed[key]) return invalid('SIGNED_CONTEXT_INVALID')
	}
	const target = '"extractedParameters":'
	if(raw.indexOf(target) !== raw.lastIndexOf(target)) return invalid('SIGNED_CONTEXT_INVALID')
	const start = raw.indexOf(target) + target.length
	if(start < target.length || !raw.startsWith(canonicalStringify(extracted), start)) return invalid('SIGNED_CONTEXT_INVALID')
}
