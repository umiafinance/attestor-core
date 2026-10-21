import assert from 'node:assert/strict'
import { createHash, webcrypto } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { after, describe, it, mock } from 'node:test'

import * as x509 from '@peculiar/x509'
import { loadX509FromPem, MOZILLA_ROOT_CA_LIST } from '@reclaimprotocol/tls'

import { refuseCertificateFetch } from '#src/server/utils/certificate-fetch.ts'
import { assertTrustedProviderChain, BLOCKED_SPKI_SHA256, DISTRUSTED_ROOTS, spkiSha256, verifyProviderCertificateChain } from '#src/server/utils/certificate-trust.ts'
import { CERTIFICATE_TRUST_REASONS } from '#src/tests/utils/certificate-trust-reasons.ts'
import { AttestorError } from '#src/utils/error.ts'
import { REJECTION_REASONS, rejectionReason } from '#src/utils/rejection-reason.ts'

type Fixture = {
	intermediates: { name: string, usage: string, issuer: string, sha256: string, spkiSha256: string, pem: string }[]
	distrustedRoots: { name: string, sha256: string, pem: string }[]
	chains: { host: string, pem: string[] }[]
}

/** impacted-intermediates.json, roots.json and chains.zip from https://emudhra.we-have-a-problem.com/ */
const fixture: Fixture = JSON.parse(readFileSync(new URL('./fixtures/emudhra-compromise-2026-10.json', import.meta.url), 'utf8'))
const logger = { info() {}, debug() {}, warn() {}, error() {}, trace() {}, child() { return logger } } as any
const fingerprint = (pem: string) => createHash('sha256').update(new Uint8Array(loadX509FromPem(pem).internal.rawData)).digest('hex')
const exercised = new Set<string>()

after(() => {
	assert.deepEqual([...exercised].sort(), [...CERTIFICATE_TRUST_REASONS].sort())
	for(const reason of CERTIFICATE_TRUST_REASONS) {
		assert.ok(Object.hasOwn(REJECTION_REASONS, reason), reason)
	}
})

function assertDistrusted(err: unknown) {
	assert.ok(err instanceof AttestorError, String(err))
	assert.equal(err.code, 'ERROR_INVALID_CLAIM')
	assert.equal(rejectionReason(err), 'CERTIFICATE_DISTRUSTED')
	exercised.add('CERTIFICATE_DISTRUSTED')
	return true
}

/** A certificate under a fresh key whose issuer name is the only thing a trust decision can see. */
async function certificateIssuedBy(issuer: string | x509.Name) {
	x509.cryptoProvider.set(webcrypto as any)
	const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' }
	const keys = await webcrypto.subtle.generateKey(alg, true, ['sign', 'verify'])
	const cert = await x509.X509CertificateGenerator.create({
		serialNumber: '01',
		subject: 'CN=provider.example',
		issuer,
		notBefore: new Date(Date.now() - 60_000),
		notAfter: new Date(Date.now() + 3_600_000),
		signingAlgorithm: alg,
		publicKey: keys.publicKey,
		signingKey: keys.privateKey
	})
	return loadX509FromPem(cert.toString('pem'))
}

describe('certificate trust', () => {
	it('blocks exactly the eight compromised keys, hashed as the root programs hash them', () => {
		assert.deepEqual([...BLOCKED_SPKI_SHA256].sort(), [...new Set(fixture.intermediates.map(i => i.spkiSha256))].sort())
		for(const { name, pem, spkiSha256: expected } of fixture.intermediates) {
			assert.equal(spkiSha256(loadX509FromPem(pem)), expected, name)
		}
	})

	it('refuses every compromised intermediate under either cross-sign', () => {
		for(const { name, issuer, pem } of fixture.intermediates) {
			assert.throws(() => assertTrustedProviderChain([loadX509FromPem(pem)]), assertDistrusted, `${name} issued by ${issuer}`)
		}
	})

	it('refuses the chains the advisory\'s test hosts serve before any signature check', async() => {
		assert.equal(fixture.chains.length, 12)
		for(const { host, pem } of fixture.chains) {
			const verify = mock.fn()
			await assert.rejects(verifyProviderCertificateChain(pem.map(loadX509FromPem), host, logger, verify as any), assertDistrusted, host)
			assert.equal(verify.mock.callCount(), 0, host)
		}
	})

	it('refuses a chain issued under a distrusted root even with an unknown key', async() => {
		assert.deepEqual(DISTRUSTED_ROOTS.map(root => fingerprint(root.serialiseToPem())).sort(), fixture.distrustedRoots.map(root => root.sha256).sort())
		for(const { name, pem } of fixture.distrustedRoots) {
			const cert = await certificateIssuedBy(new x509.X509Certificate(pem).subjectName)
			assert.throws(() => assertTrustedProviderChain([cert]), assertDistrusted, name)
		}
	})

	it('passes any other chain to the TLS library with the refusing fetcher', async() => {
		const cert = await certificateIssuedBy('CN=emSign Root CA - G1,OU=emSign PKI,O=eMudhra Technologies Limited,C=IN')
		assertTrustedProviderChain([cert])
		const verify = mock.fn(async() => {})
		await verifyProviderCertificateChain([cert], 'provider.example', logger, verify as any)
		assert.equal(verify.mock.callCount(), 1)
		assert.deepEqual(verify.mock.calls[0].arguments, [[cert], 'provider.example', logger, refuseCertificateFetch])
	})

	it('overrides roots the pinned TLS bundle still trusts', () => {
		// Fails after a library bump that drops a root: then decide whether the override stays.
		const bundled = new Set(MOZILLA_ROOT_CA_LIST.map(fingerprint))
		for(const { name, sha256 } of fixture.distrustedRoots) {
			assert.ok(bundled.has(sha256), name)
		}
	})

	it('is the only chain verifier the handshake processor calls', () => {
		const source = readFileSync(new URL('../server/utils/process-handshake.ts', import.meta.url), 'utf8')
		assert.ok(!source.includes('verifyCertificateChain('))
		assert.equal(source.match(/verifyProviderCertificateChain\(/g)?.length, 2)
	})
})
