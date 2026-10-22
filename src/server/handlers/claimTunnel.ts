import { CLAIM_CHAIN_IDS } from '#src/config/claim-chain-ids.ts'
import { CLAIM_EPOCH } from '#src/config/claim-epoch.ts'
import { MAX_CLAIM_TIMESTAMP_DIFF_S } from '#src/config/index.ts'
import { ClaimTunnelResponse } from '#src/proto/api.ts'
import { getApm } from '#src/server/utils/apm.ts'
import { assertTranscriptsMatch, assertValidClaimRequest } from '#src/server/utils/assert-valid-claim-request.ts'
import { signClaimResponse } from '#src/server/utils/sign-claim-response.ts'
import { assertAuthenticatedClaimAuthority } from '#src/server/utils/host-policy.ts'
import { assertSupportedInputContext, assertSupportedSignedContext } from '#src/server/utils/claim-context-policy.ts'
import type { RPCHandler } from '#src/types/index.ts'
import {
	AttestorError,
	getIdentifierFromClaimInfo,
	unixTimestampSeconds
} from '#src/utils/index.ts'
import { rejection, withRejectionReason } from '#src/utils/rejection-reason.ts'

export const claimTunnel: RPCHandler<'claimTunnel'> = async(
	claimRequest,
	{ tx, logger, client }
) => {
	const {
		request,
		data: { timestampS } = {},
	} = claimRequest
	const tunnel = client.getTunnel(request?.id!)
	try {
		await tunnel.close()
	} catch(err) {
		logger.debug({ err }, 'error closing tunnel')
	}

	if(tx) {
		const transcriptBytes = tunnel.transcript.reduce(
			(acc, { message }) => acc + message.length,
			0
		)
		tx?.setLabel('transcriptBytes', Math.min(transcriptBytes, 100_000_000))
	}

	// we throw an error for cases where the attestor cannot prove
	// the user's request is faulty. For eg. if the user sends a
	// "createRequest" that does not match the tunnel's actual
	// create request -- the attestor cannot prove that the user
	// is lying. In such cases, we throw a bad request error.
	// Same goes for matching the transcript.
	if(
		tunnel.createRequest?.host !== request?.host
		|| tunnel.createRequest?.port !== request?.port
		|| tunnel.createRequest?.geoLocation !== request?.geoLocation
		|| tunnel.createRequest?.proxySessionId !== request?.proxySessionId
	) {
		throw rejection('ERROR_BAD_REQUEST', 'TUNNEL_REQUEST_MISMATCH', 'Tunnel request does not match')
	}

	try {
		assertTranscriptsMatch(claimRequest.transcript, tunnel.transcript)
	} catch(err) {
		throw withRejectionReason(err, 'TRANSCRIPT_MISMATCH', 'ERROR_BAD_REQUEST')
	}
	let inputContext: ReturnType<typeof assertSupportedInputContext>
	try {
		inputContext = assertSupportedInputContext(claimRequest.data?.context, client.authIdentity, CLAIM_CHAIN_IDS)
	} catch(err) {
		client.removeTunnel(request.id)
		throw err
	}

	const res = ClaimTunnelResponse.create({ request: claimRequest })
	try {
		const now = unixTimestampSeconds()
		if(Math.floor(timestampS! - now) > MAX_CLAIM_TIMESTAMP_DIFF_S) {
			throw rejection(
				'ERROR_INVALID_CLAIM',
				'CLAIM_TIMESTAMP_SKEW',
				`Timestamp provided ${timestampS} is too far off. Current time is ${now}`
			)
		}

		const assertTx = getApm()
			?.startTransaction('assertValidClaimRequest', { childOf: tx })

		try {
			const claim = await assertValidClaimRequest(
				claimRequest,
				client.metadata,
				logger
			)
			res.claim = {
				...claim,
				identifier: getIdentifierFromClaimInfo(claim),
				epoch: CLAIM_EPOCH
			}
		} catch(err) {
			assertTx?.setOutcome('failure')
			throw err
		} finally {
			assertTx?.end()
		}
	} catch(err) {
		logger.error({ err }, 'invalid claim request')
		const attestorErr = AttestorError.fromError(err, 'ERROR_INVALID_CLAIM')
		res.error = attestorErr.toProto()
	}

	// Strip transcript before signing -- client already has it.
	// Reduces response size dramatically for STARK proofs.
	if(res.request) {
		res.request.transcript = []
	}
	if(res.claim) {
		try {
			assertSupportedSignedContext(res.claim.context, inputContext)
			assertAuthenticatedClaimAuthority(
				res.claim,
				client.authHostWhitelist ?? [],
				tunnel.createRequest?.host,
				tunnel.createRequest?.port
			)
		} catch(err) {
			client.removeTunnel(request.id)
			throw err
		}
	}

	await signClaimResponse(res, ClaimTunnelResponse, client)

	// remove tunnel from client -- to free up our mem
	client.removeTunnel(request.id)
	if(res.error) logger.warn('claim tunnel rejected')
	else logger.info('claim tunnel completed')

	return res
}
