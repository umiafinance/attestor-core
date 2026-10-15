import assert from 'node:assert/strict'
import { deflateSync } from 'node:zlib'
import { it } from 'node:test'
import { ClaimTunnelRequest, ZKProofEngine } from '#src/proto/api.ts'
import { restoreStwoProofs } from '#src/server/utils/stwo-proof-compression.ts'

const magic = Buffer.from('UMIA_STWO_ZLIB_V1\0')
function request(proofData: Uint8Array, engine = ZKProofEngine.ZK_ENGINE_STWO) {
	return ClaimTunnelRequest.create({
		zkEngine: engine,
		transcript: [{ reveal: { zkReveal: { proofs: [{ proofData }] } } }]
	})
}

it('restores compressed Stwo proofs and accepts legacy proof bytes', () => {
	const raw = new Uint8Array(200_000).fill(0x41)
	const compressed = request(Buffer.concat([magic, deflateSync(raw)]))
	restoreStwoProofs(compressed)
	assert.equal(Buffer.compare(compressed.transcript[0].reveal?.zkReveal?.proofs[0].proofData ?? new Uint8Array(), raw), 0)
	const legacy = request(raw)
	restoreStwoProofs(legacy)
	assert.equal(legacy.transcript[0].reveal?.zkReveal?.proofs[0].proofData, raw)
})

it('rejects compressed proofs for another engine and bounded decompression', () => {
	const raw = new Uint8Array(4 * 1024 * 1024 + 1).fill(0x41)
	const encoded = Buffer.concat([magic, deflateSync(raw)])
	assert.throws(() => restoreStwoProofs(request(encoded, ZKProofEngine.ZK_ENGINE_SNARKJS)))
	assert.throws(() => restoreStwoProofs(request(encoded)))
	assert.throws(() => restoreStwoProofs(request(Buffer.concat([magic, new Uint8Array([1, 2, 3])]))))
})
