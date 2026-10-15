import type { ClaimTeeBundleResponse, ClaimTunnelResponse } from '#src/proto/api.ts'
import { getAttestorAddress, signAsAttestor } from '#src/server/utils/generics.ts'
import type { IAttestorServerSocket } from '#src/types/index.ts'
import { createSignDataForClaim } from '#src/utils/claims.ts'

type SignableResponse = ClaimTunnelResponse | ClaimTeeBundleResponse
type SignerClient = Pick<IAttestorServerSocket, 'metadata' | 'assertAuthActive'>

export async function signClaimResponse<T extends SignableResponse>(
	response: T,
	codec: { encode(message: T): { finish(): Uint8Array } },
	client: SignerClient
) {
	client.assertAuthActive()
	const signatureType = client.metadata.signatureType
	const attestorAddress = getAttestorAddress(signatureType)
	const claimSignature = response.claim
		? await signAsAttestor(createSignDataForClaim(response.claim), signatureType)
		: new Uint8Array()
	client.assertAuthActive()
	const resultSignature = await signAsAttestor(codec.encode(response).finish(), signatureType)
	client.assertAuthActive()
	response.signatures = { attestorAddress, claimSignature, resultSignature }
}
