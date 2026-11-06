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


it('admits an Echo-sized compressed transcript above the former 32 MiB inflated limit', () => {
	// Synthetic bytes only: same total and maximum as the client diagnostic;
	// this exercises admission, not proof verification or a real Echo capture.
	const sizes = [...Array(28).fill(1_473_373), 1_201_077]
	assert.equal(sizes.reduce((total, size) => total + size, 0), 42_455_521)
	const claim = ClaimTunnelRequest.create({
		zkEngine: ZKProofEngine.ZK_ENGINE_STWO,
		transcript: sizes.map(size => ({ reveal: { zkReveal: { proofs: [{
			proofData: Buffer.concat([magic, deflateSync(new Uint8Array(size).fill(0x41))])
		}] } } }))
	})
	restoreStwoProofs(claim)
	assert.deepEqual(claim.transcript.map(packet => packet.reveal?.zkReveal?.proofs[0].proofData.length), sizes)
})

it('bounds cumulative inflated bytes across packets, including mixed compressed and raw proofs', () => {
	const raw = new Uint8Array(4 * 1024 * 1024).fill(0x41)
	const encoded = Buffer.concat([magic, deflateSync(raw)])
	for(const compressed of [false, true]) {
		const claim = ClaimTunnelRequest.create({
			zkEngine: ZKProofEngine.ZK_ENGINE_STWO,
			transcript: Array.from({ length: 32 }, (_, index) => ({
				reveal: { zkReveal: { proofs: [{ proofData: compressed && index % 2 ? encoded : raw }] } }
			}))
		})
		// Exactly 128 MiB fits; the next byte in a separate packet must fail.
		restoreStwoProofs(claim)
		claim.transcript.push(ClaimTunnelRequest.create({
			transcript: [{ reveal: { zkReveal: { proofs: [{ proofData: new Uint8Array(1) }] } } }]
		}).transcript[0])
		assert.throws(() => restoreStwoProofs(claim), /Total proof bytes too large/)
	}
})

it('keeps the individual raw proof limit at 4 MiB', () => {
	assert.throws(() => restoreStwoProofs(request(new Uint8Array(4 * 1024 * 1024 + 1))), /Proof too large/)
})

for(const [chunks, total] of [[45, 65_757_369], [49, 71_514_393], [44, 64_821_276]]) {
	it(`restores the reported Echo transcript with ${chunks} proofs and ${total} bytes`, () => {
		// Synthetic admission fixture: no account data or real cryptographic proof.
		const regularSize = Math.floor(total / chunks)
		const sizes = Array.from({ length: chunks }, (_, i) => regularSize + (i < total % chunks ? 1 : 0))
		const claim = ClaimTunnelRequest.create({
			zkEngine: ZKProofEngine.ZK_ENGINE_STWO,
			transcript: sizes.map(size => ({ reveal: { zkReveal: { proofs: [{
				proofData: Buffer.concat([magic, deflateSync(new Uint8Array(size).fill(0x41))])
			}] } } }))
		})
		restoreStwoProofs(claim)
		assert.deepEqual(claim.transcript.map(packet => packet.reveal?.zkReveal?.proofs[0].proofData.length), sizes)
	})
}
