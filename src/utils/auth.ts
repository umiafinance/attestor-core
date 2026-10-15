import { getBytes } from 'ethers'

import { DEFAULT_AUTH_EXPIRY_S, MAX_AUTH_CLOCK_SKEW_S, MAX_AUTH_LIFETIME_S } from '#src/config/index.ts'
import type { AuthenticationRequest, ServiceSignatureType } from '#src/proto/api.ts'
import { AuthenticatedUserData } from '#src/proto/api.ts'
import { getEnvVariable } from '#src/utils/env.ts'
import { AttestorError } from '#src/utils/error.ts'
import { rejection } from '#src/utils/rejection-reason.ts'
import { unixTimestampSeconds } from '#src/utils/generics.ts'
import { SelectedServiceSignature, SIGNATURES } from '#src/utils/signatures/index.ts'

export async function assertValidAuthRequest(
	request: AuthenticationRequest | undefined,
	signatureType: ServiceSignatureType
) {
	const publicKey = getEnvVariable('AUTHENTICATION_PUBLIC_KEY')
	// nothing to verify
	if(!request) {
		// if pub key is provided -- but user didn't attempt to
		// authenticate, then we should throw an error
		if(publicKey) {
			throw rejection('ERROR_AUTHENTICATION_FAILED', 'AUTH_REQUIRED', 'User must be authenticated')
		}

		return
	}

	if(!publicKey) {
		throw new AttestorError(
			'ERROR_BAD_REQUEST',
			'The attestor is not configured for authentication'
		)
	}

	const { signature, data } = request
	if(!data) {
		throw rejection('ERROR_AUTHENTICATION_FAILED', 'AUTH_INVALID', 'Missing data in auth request')
	}

	assertAuthNotExpired(data)

	const proto = AuthenticatedUserData.encode(data).finish()
	const signatureAlg = SIGNATURES[signatureType]
	const address = signatureAlg.getAddress(
		getBytes(publicKey)
	)
	const verified = await signatureAlg
		.verify(proto, signature, address)
	assertAuthNotExpired(data)
	if(!verified) {
		throw rejection('ERROR_AUTHENTICATION_FAILED', 'AUTH_INVALID', 'Signature verification failed')
	}

	assertAuthLifetime(data)
}

// A leaked auth stays usable until expiry, and there is no revocation channel.
function assertAuthLifetime({ createdAt, expiresAt }: AuthenticatedUserData) {
	if(
		createdAt > unixTimestampSeconds() + MAX_AUTH_CLOCK_SKEW_S
		|| expiresAt <= createdAt
		|| expiresAt - createdAt > MAX_AUTH_LIFETIME_S
	) {
		throw rejection('ERROR_AUTHENTICATION_FAILED', 'AUTH_LIFETIME_INVALID', 'Authentication lifetime is not allowed')
	}
}

function assertAuthNotExpired(data: AuthenticatedUserData) {
	if(!Number.isSafeInteger(data.expiresAt) || data.expiresAt <= unixTimestampSeconds()) {
		throw rejection('ERROR_AUTHENTICATION_FAILED', 'AUTH_EXPIRED', 'Authentication request has expired')
	}
}

/**
 * Create an authentication request with the given data and private key,
 * which can then be used to authenticate with the service.
 */
export async function createAuthRequest(
	_data: Partial<AuthenticatedUserData>,
	privateKey: string
) {
	const createdAt = unixTimestampSeconds()
	const data: AuthenticatedUserData = {
		createdAt,
		expiresAt: createdAt + DEFAULT_AUTH_EXPIRY_S,
		id: '',
		hostWhitelist: [],
		..._data,
	}
	const proto = AuthenticatedUserData.encode(data).finish()
	const signature = await SelectedServiceSignature
		.sign(proto, privateKey)
	const request: AuthenticationRequest = {
		data,
		signature
	}

	return request
}