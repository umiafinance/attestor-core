import assert from 'node:assert/strict'
import { it, mock } from 'node:test'

import { ClaimTunnelRequest, ServiceSignatureType, ZKProofEngine } from '#src/proto/api.ts'
import { SIGNATURES } from '#src/utils/signatures/index.ts'

mock.module('#src/server/utils/process-handshake.ts', {
	namedExports: {
		async processHandshake() {
			return {
				hostname: 'other.example.com', tlsVersion: 'TLS1_3',
				cipherSuite: 'TLS_AES_128_GCM_SHA256', nextMsgIndex: 0
			}
		}
	}
})
const { assertValidClaimRequest } = await import('#src/server/utils/assert-valid-claim-request.ts')
const logger = { info() {}, debug() {}, warn() {}, error() {} } as any

it('rejects verified TLS SNI that differs from the recorded tunnel host', async() => {
	const verify = mock.method(SIGNATURES[ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH], 'verify', async() => true)
	try {
		const request = ClaimTunnelRequest.create({
			request: { id: 1, host: 'api.example.com', port: 443 },
			data: { owner: '0x0000000000000000000000000000000000000001' },
			signatures: { requestSignature: new Uint8Array([1]) },
			zkEngine: ZKProofEngine.ZK_ENGINE_GNARK,
			transcript: []
		})
		await assert.rejects(
			assertValidClaimRequest(request, { signatureType: ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH } as any, logger),
			/Expected server name api.example.com, got other.example.com/
		)
	} finally {
		verify.mock.restore()
	}
})
