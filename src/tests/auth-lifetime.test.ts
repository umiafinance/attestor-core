import assert from 'node:assert/strict'
import { describe, it, mock } from 'node:test'
import { Wallet } from 'ethers'

import { AuthSession, type AuthClock } from '#src/server/utils/auth-session.ts'
import { assertValidAuthRequest, createAuthRequest } from '#src/utils/auth.ts'
import { SelectedServiceSignature, SelectedServiceSignatureType } from '#src/utils/signatures/index.ts'
import { AttestorError } from '#src/utils/error.ts'

class FakeClock implements AuthClock {
	ms = 0
	cleared = 0
	private nextId = 0
	private timers = new Map<number, { at: number, callback: () => void }>()

	nowMs() { return this.ms }
	setTimeout(callback: () => void, delayMs: number) {
		const id = ++this.nextId
		this.timers.set(id, { at: this.ms + delayMs, callback })
		return id as unknown as ReturnType<typeof setTimeout>
	}
	clearTimeout(timer: ReturnType<typeof setTimeout>) {
		if(this.timers.delete(timer as unknown as number)) this.cleared++
	}
	advanceTo(ms: number) {
		this.ms = ms
		while(true) {
			const due = [...this.timers].find(([, timer]) => timer.at <= ms)
			if(!due) break
			this.timers.delete(due[0])
			due[1].callback()
		}
	}
	get pending() { return this.timers.size }
}

function authData(expiresAt: number) {
	return { id: 'session', createdAt: 0, expiresAt, hostWhitelist: ['example.com'] }
}

function isAuthError(err: unknown) {
	return err instanceof AttestorError && err.code === 'ERROR_AUTHENTICATION_FAILED'
}

describe('auth deadline', () => {
	it('allows before expiry and rejects at equality; activity does not change the deadline', () => {
		const clock = new FakeClock()
		clock.ms = 9_000
		let closes = 0
		const lifetime = new AuthSession(authData(10), () => closes++, clock)
		for(const ms of [9_100, 9_500, 9_999]) {
			clock.advanceTo(ms)
			lifetime.assertActive()
		}
		clock.advanceTo(10_000)
		assert.throws(() => lifetime.assertActive(), isAuthError)
		assert.equal(closes, 1)
		assert.equal(clock.pending, 0)
		lifetime.dispose()
		assert.equal(closes, 1)
	})

	it('clears its timer once on close or error and expires one session without closing another', () => {
		const clock = new FakeClock()
		const closed: string[] = []
		const a = new AuthSession(authData(10), () => closed.push('a'), clock)
		const b = new AuthSession(authData(20), () => closed.push('b'), clock)
		clock.advanceTo(10_000)
		assert.deepEqual(closed, ['a'])
		b.assertActive()
		b.dispose()
		b.dispose()
		clock.advanceTo(20_000)
		assert.deepEqual(closed, ['a'])
		assert.equal(clock.pending, 0)
		assert.equal(clock.cleared, 1)
		a.dispose()
	})

	it('rejects missing, invalid, and expired init authentication, including equality', async() => {
		const key = Wallet.createRandom()
		process.env.AUTHENTICATION_PUBLIC_KEY = key.publicKey
		const now = 100_000
		const dateMock = mock.method(Date, 'now', () => now * 1000)
		try {
			await assert.rejects(
				assertValidAuthRequest(undefined, SelectedServiceSignatureType),
				isAuthError
			)
			const valid = await createAuthRequest({ expiresAt: now + 1 }, key.privateKey)
			await assertValidAuthRequest(valid, SelectedServiceSignatureType)
			for(const auth of [
				await createAuthRequest({ expiresAt: now + 1 }, Wallet.createRandom().privateKey),
				await createAuthRequest({ expiresAt: now }, key.privateKey),
				await createAuthRequest({ expiresAt: now - 1 }, key.privateKey)
			]) {
				await assert.rejects(
					assertValidAuthRequest(auth, SelectedServiceSignatureType),
					isAuthError
				)
			}
		} finally {
			dateMock.mock.restore()
			delete process.env.AUTHENTICATION_PUBLIC_KEY
		}
	})

	it('rejects a valid signature when verification crosses the expiry boundary', async() => {
		const key = Wallet.createRandom()
		process.env.AUTHENTICATION_PUBLIC_KEY = key.publicKey
		let now = 100_000
		const dateMock = mock.method(Date, 'now', () => now * 1000)
		const auth = await createAuthRequest({ expiresAt: now + 1 }, key.privateKey)
		const originalVerify = SelectedServiceSignature.verify.bind(SelectedServiceSignature)
		let release!: () => void
		const gate = new Promise<void>(resolve => { release = resolve })
		const verifyMock = mock.method(SelectedServiceSignature, 'verify', async(...args) => {
			await gate
			return originalVerify(...args)
		})
		try {
			const pending = assertValidAuthRequest(auth, SelectedServiceSignatureType)
			now++
			release()
			await assert.rejects(pending, isAuthError)
		} finally {
			verifyMock.mock.restore()
			dateMock.mock.restore()
			delete process.env.AUTHENTICATION_PUBLIC_KEY
		}
	})
})
