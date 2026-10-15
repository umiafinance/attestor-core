import assert from 'node:assert/strict'
import { describe, it, mock } from 'node:test'

import { AttestorError } from '#src/utils/error.ts'
import { inputContext, signedContext, TEST_SESSION_ID, testAuthIdentity } from '#src/tests/utils/claim-context.ts'

process.env.CLAIM_EPOCH = '2'

process.env.CLAIM_CHAIN_IDS = '10143'
process.env.PRIVATE_KEY = '0x0000000000000000000000000000000000000000000000000000000000000001'

const claimInfo = {
	provider: 'http', parameters: '{"url":"https://example.com/"}', context: signedContext(),
	owner: '0x0000000000000000000000000000000000000001',
	timestampS: Math.floor(Date.now() / 1000)
}
const logger = { info() {}, debug() {}, warn() {}, error() {} }
let validationWait: (() => Promise<void>) | undefined

mock.module('#src/server/utils/assert-valid-claim-request.ts', {
	namedExports: {
		assertTranscriptsMatch() {},
		async assertValidClaimRequest() {
			await validationWait?.()
			return { ...claimInfo }
		},
		async assertValidProviderTranscript() {
			await validationWait?.()
			return { ...claimInfo }
		}
	}
})
const [{ claimTunnel }, { ServiceSignatureType, AttestorVersion, ClaimTunnelRequest }, { SIGNATURES }] = await Promise.all([
	import('#src/server/handlers/claimTunnel.ts'),
	import('#src/proto/api.ts'),
	import('#src/utils/signatures/index.ts')
])
const signatureType = ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH

function deferred() {
	let resolve!: () => void
	const promise = new Promise<void>(r => { resolve = r })
	return { promise, resolve }
}

function setup() {
	let now = 9
	const client = {
		authIdentity: testAuthIdentity(),
		authHostWhitelist: Object.freeze(['example.com']),
		metadata: { signatureType, clientVersion: AttestorVersion.ATTESTOR_VERSION_3_2_0 },
		assertAuthActive() {
			if(now >= 10) throw new AttestorError('ERROR_AUTHENTICATION_FAILED', 'Authentication expired')
		},
		getTunnel() {
			return {
				createRequest: { host: 'example.com', port: 443, geoLocation: '', proxySessionId: '' }, transcript: [], async close() {}
			}
		},
		removeTunnel() {},
	}
	return { client, expire: () => { now = 10 } }
}

function request(client: ReturnType<typeof setup>['client']) {
	const ctx = { logger, client } as unknown as Parameters<typeof claimTunnel>[1]
	return claimTunnel(ClaimTunnelRequest.create({
		request: { id: 1, host: 'example.com', port: 443 },
		data: { timestampS: claimInfo.timestampS, context: inputContext() }
	}), ctx)
}

function isAuthError(err: unknown) {
	return err instanceof AttestorError && err.code === 'ERROR_AUTHENTICATION_FAILED'
}

describe('claimTunnel auth deadline', () => {
		it('rejects when validation crosses the deadline before either signature', async() => {
			const entered = deferred()
			const release = deferred()
			validationWait = async() => { entered.resolve(); await release.promise }
			const session = setup()
			const sign = mock.method(SIGNATURES[signatureType], 'sign')
			try {
				const pending = request(session.client)
				await entered.promise
				session.expire()
				release.resolve()
				await assert.rejects(pending, isAuthError)
				assert.equal(sign.mock.calls.length, 0)
			} finally {
				sign.mock.restore()
				validationWait = undefined
			}
		})

		for(const heldSign of [1, 2]) {
			it(`suppresses delivery when signature ${heldSign} resolves after expiry`, async() => {
				const entered = deferred()
				const release = deferred()
				validationWait = undefined
				const session = setup()
				let calls = 0
				const sign = mock.method(SIGNATURES[signatureType], 'sign', async() => {
					calls++
					if(calls === heldSign) { entered.resolve(); await release.promise }
					return new Uint8Array([1])
				})
				try {
					const pending = request(session.client)
					await entered.promise
					session.expire()
					release.resolve()
					await assert.rejects(pending, isAuthError)
					assert.equal(calls, heldSign)
				} finally {
					sign.mock.restore()
				}
			})
		}
})
