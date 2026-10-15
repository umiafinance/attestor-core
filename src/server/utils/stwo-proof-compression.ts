import { inflateSync } from 'node:zlib'
import { ZKProofEngine, type ClaimTunnelRequest } from '#src/proto/api.ts'
import { AttestorError } from '#src/utils/index.ts'

const MAGIC = Buffer.from('UMIA_STWO_ZLIB_V1\0')
const MAX_PROOF_BYTES = 4 * 1024 * 1024
const MAX_TOTAL_PROOF_BYTES = 32 * 1024 * 1024

/** Called only after the signed request has been verified. */
export function restoreStwoProofs(request: ClaimTunnelRequest) {
	let totalBytes = 0
	for(const packet of request.transcript) {
		for(const proof of packet.reveal?.zkReveal?.proofs ?? []) {
			const encoded = proof.proofData
			if(encoded.length >= MAGIC.length
				&& Buffer.compare(encoded.subarray(0, MAGIC.length), MAGIC) === 0) {
				if(request.zkEngine !== ZKProofEngine.ZK_ENGINE_STWO) {
					throw AttestorError.badRequest('Compressed proof requires Stwo')
				}
				try {
					proof.proofData = inflateSync(encoded.subarray(MAGIC.length), {
						maxOutputLength: MAX_PROOF_BYTES
					})
				} catch {
					throw AttestorError.badRequest('Invalid compressed proof')
				}
			}
			if(proof.proofData.length > MAX_PROOF_BYTES) {
				throw AttestorError.badRequest('Proof too large')
			}
			totalBytes += proof.proofData.length
			if(totalBytes > MAX_TOTAL_PROOF_BYTES) {
				throw AttestorError.badRequest('Total proof bytes too large')
			}
		}
	}
}
