import { isIP } from 'node:net'

import type { ProviderClaimInfo } from '#src/proto/api.ts'
import { canonicalStringify } from '#src/utils/claims.ts'
import { rejection } from '#src/utils/rejection-reason.ts'

const MAX_DNS_NAME_LENGTH = 253
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

export function isCanonicalAuthHostname(host: unknown): host is string {
	if(typeof host !== 'string' || host.length > MAX_DNS_NAME_LENGTH || isIP(host)) return false
	if(host === 'localhost' || ['.localhost', '.local', '.internal'].some(suffix => host.endsWith(suffix))) return false
	const labels = host.split('.')
	if(labels.length < 2 || !labels.every(label => DNS_LABEL.test(label))) return false
	try {
		const url = new URL(`https://${host}`)
		return url.hostname === host && !isIP(url.hostname)
	} catch {
		return false
	}
}

export function assertCanonicalHostWhitelist(hostWhitelist: readonly string[]) {
	if(!Array.isArray(hostWhitelist) || !hostWhitelist.length) {
		throw rejection('ERROR_BAD_REQUEST', 'HOST_LIST_INVALID', 'Authenticated host list is empty')
	}
	let previous: string | undefined
	for(const entry of hostWhitelist) {
		if(!isCanonicalAuthHostname(entry) || (previous !== undefined && previous >= entry)) {
			throw rejection('ERROR_BAD_REQUEST', 'HOST_LIST_INVALID', 'Authenticated host list is not canonical')
		}
		previous = entry
	}
}

export function assertAuthenticatedTunnelHost(
	hostWhitelist: readonly string[],
	host: string,
	port: number
) {
	assertCanonicalHostWhitelist(hostWhitelist)
	if(port !== 443) throw rejection('ERROR_BAD_REQUEST', 'PORT_NOT_ALLOWED', 'Authenticated tunnel requires port 443')
	if(!hostWhitelist.includes(host)) throw rejection('ERROR_BAD_REQUEST', 'HOST_NOT_ALLOWED', 'Host not allowed by auth request')
}

export function assertAuthenticatedClaimAuthority(
	claim: ProviderClaimInfo,
	hostWhitelist: readonly string[],
	tunnelHost: string | undefined,
	tunnelPort: number | undefined
) {
	if(!tunnelHost || tunnelPort === undefined) {
		throw rejection('ERROR_BAD_REQUEST', 'TUNNEL_REQUEST_MISMATCH', 'Authenticated claim has no recorded tunnel authority')
	}
	assertAuthenticatedTunnelHost(hostWhitelist, tunnelHost, tunnelPort)
	if(claim.provider !== 'http') {
		throw rejection('ERROR_BAD_REQUEST', 'CLAIM_PROVIDER_UNSUPPORTED', 'Authenticated claim provider is unsupported')
	}

	let params: unknown
	try {
		params = JSON.parse(claim.parameters)
	} catch {
		throw rejection('ERROR_BAD_REQUEST', 'CLAIM_PARAMS_INVALID', 'Authenticated claim URL is invalid')
	}
	if(!params || typeof params !== 'object' || Array.isArray(params)
		|| canonicalStringify(params) !== claim.parameters) {
		throw rejection('ERROR_BAD_REQUEST', 'CLAIM_PARAMS_INVALID', 'Authenticated claim parameters are not canonical')
	}
	const urlText = (params as { url?: unknown }).url
	if(typeof urlText !== 'string') {
		throw rejection('ERROR_BAD_REQUEST', 'CLAIM_PARAMS_INVALID', 'Authenticated claim URL is invalid')
	}
	// Check raw authority before URL parsing can normalize case, IDNA, or default port.
	const authority = /^https:\/\/([^/?#]+)(?:[/?#]|$)/.exec(urlText)?.[1]
	if(authority !== tunnelHost && authority !== `${tunnelHost}:443`) {
		throw rejection('ERROR_BAD_REQUEST', 'CLAIM_URL_MISMATCH', 'Authenticated claim authority differs from tunnel')
	}
	let url: URL
	try {
		url = new URL(urlText)
	} catch {
		throw rejection('ERROR_BAD_REQUEST', 'CLAIM_URL_MISMATCH', 'Authenticated claim URL is not canonical HTTPS on port 443')
	}
	if(
		url.protocol !== 'https:' || url.hostname !== tunnelHost || url.port !== ''
		|| url.username || url.password || url.hash
	) throw rejection('ERROR_BAD_REQUEST', 'CLAIM_URL_MISMATCH', 'Authenticated claim URL is not canonical HTTPS on port 443')
}
