import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { describe, it, mock } from 'node:test'

import type { ClaimTunnelResponse } from '#src/proto/api.ts'
import { inputContext, signedContext, TEST_SESSION_ID, testAuthIdentity } from '#src/tests/utils/claim-context.ts'

process.env.CLAIM_EPOCH = '2'

process.env.CLAIM_CHAIN_IDS = '10143'
process.env.PRIVATE_KEY = '0x0000000000000000000000000000000000000000000000000000000000000001'

const claimInfo = {
	provider: 'http',
	parameters: '{"url":"https://example.com/"}',
	context: signedContext(),
	owner: '0x0000000000000000000000000000000000000001',
	timestampS: Math.floor(Date.now() / 1000)
}
const logger = { info() {}, debug() {}, warn() {}, error() {} }

mock.module('#src/server/utils/assert-valid-claim-request.ts', {
	namedExports: {
		assertTranscriptsMatch() {},
		async assertValidClaimRequest() { return { ...claimInfo } },
		async assertValidProviderTranscript() { return { ...claimInfo } }
	}
})
const [{ parseClaimEpoch }, { claimTunnel }, { claimTeeBundle }, proto, claims, signatures] = await Promise.all([
	import('#src/config/claim-epoch.ts'),
	import('#src/server/handlers/claimTunnel.ts'),
	import('#src/server/handlers/claimTeeBundle.ts'),
	import('#src/proto/api.ts'),
	import('#src/utils/claims.ts'),
	import('#src/utils/signatures/index.ts')
])
const signatureType = proto.ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH
const verify = signatures.SIGNATURES[signatureType].verify
const wrongSigner = '0x0000000000000000000000000000000000000002'
const client = {
	authIdentity: testAuthIdentity(),
	authHostWhitelist: Object.freeze(['example.com']),
	metadata: { signatureType, clientVersion: proto.AttestorVersion.ATTESTOR_VERSION_3_2_0 },
	assertAuthActive() {},
	getTunnel() {
		return {
			createRequest: { host: 'example.com', port: 443, geoLocation: '', proxySessionId: '' },
			transcript: [],
			async close() {}
		}
	},
	removeTunnel() {}
}

async function assertSignatures(res: ClaimTunnelResponse) {
	const claim = res.claim
	const signature = res.signatures
	assert.ok(claim)
	assert.ok(signature)
	assert.equal(claim.epoch, 2)
	assert.ok(signature.claimSignature.length)
	assert.ok(signature.resultSignature.length)
	const address = signature.attestorAddress
	const claimBytes = new TextEncoder().encode(claims.createSignDataForClaim(claim))
	assert.equal(await verify(claimBytes, signature.claimSignature, address), true)
	assert.equal(await verify(proto.ClaimTunnelResponse.encode({ ...res, signatures: undefined }).finish(), signature.resultSignature, address), true)
	assert.equal(await verify(claimBytes, signature.claimSignature, wrongSigner), false)
	assert.equal(await verify(proto.ClaimTunnelResponse.encode({ ...res, signatures: undefined }).finish(), signature.resultSignature, wrongSigner), false)
	const tamperedClaim = { ...claim, epoch: 3 }
	const tampered = { ...res, claim: tamperedClaim, signatures: undefined }
	const tamperedClaimBytes = new TextEncoder().encode(claims.createSignDataForClaim(tamperedClaim))
	assert.equal(await verify(tamperedClaimBytes, signature.claimSignature, address), false)
	assert.equal(await verify(proto.ClaimTunnelResponse.encode(tampered).finish(), signature.resultSignature, address), false)
}

describe('CLAIM_EPOCH', () => {
	it('accepts only canonical positive decimal uint32 values', () => {
		for(const [raw, expected] of [['1', 1], ['2', 2], ['4294967295', 4294967295]] as const) {
			assert.equal(parseClaimEpoch(raw), expected)
		}
		for(const raw of [undefined, '', '0', '-1', '+1', '01', ' 1', '1 ', '1.0', '1e0', '0x1', '4294967296', '999999999999999999999999']) {
			assert.throws(() => parseClaimEpoch(raw), /CLAIM_EPOCH/)
		}
	})

	it('fails before the server listener for missing and invalid epochs', () => {
		for(const raw of [undefined, '0', '4294967296']) {
			const env = { ...process.env }
			if(raw === undefined) delete env.CLAIM_EPOCH
			else env.CLAIM_EPOCH = raw
			const result = spawnSync(process.execPath, ['--experimental-strip-types', 'src/scripts/start-server.ts'], { env, encoding: 'utf8', timeout: 10_000 })
			assert.notEqual(result.status, 0)
			assert.match(result.stderr, /CLAIM_EPOCH must be a canonical decimal uint32/)
		}
	})

	it('stamps and signs claimTunnel at epoch 2 in the hardened layer', async () => {
		const ctx = { logger, client } as unknown as Parameters<typeof claimTunnel>[1]
		const tunnel = await claimTunnel(proto.ClaimTunnelRequest.create({
			request: { id: 1, host: 'example.com', port: 443 },
			data: { timestampS: claimInfo.timestampS, context: inputContext() }
		}), ctx)
		await assertSignatures(tunnel)

		await assert.rejects(claimTeeBundle(proto.ClaimTeeBundleRequest.create({
			verificationBundle: new Uint8Array(),
			data: { ...claimInfo }
		}), ctx), /verified endpoint binding/)
	})
})
