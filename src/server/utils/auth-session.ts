import type { AuthenticatedUserData } from '#src/proto/api.ts'
import { rejection } from '#src/utils/rejection-reason.ts'

type Timer = ReturnType<typeof setTimeout>
export type AuthClock = {
	nowMs(): number
	setTimeout(callback: () => void, delayMs: number): Timer
	clearTimeout(timer: Timer): void
}

const SYSTEM_CLOCK: AuthClock = {
	nowMs: Date.now,
	setTimeout: (callback, delayMs) => setTimeout(callback, delayMs),
	clearTimeout: timer => clearTimeout(timer)
}
const MAX_TIMEOUT_MS = 2_147_483_647

export function authExpiredError() {
	return rejection('ERROR_AUTHENTICATION_FAILED', 'AUTH_EXPIRED', 'Authentication expired')
}

export class AuthSession {
	readonly identity: string
	readonly hostWhitelist: readonly string[]
	private readonly deadlineMs: number
	private readonly onExpire: () => void
	private readonly clock: AuthClock
	private timer: Timer | undefined
	private disposed = false

	constructor(
		data: AuthenticatedUserData,
		onExpire: () => void,
		clock: AuthClock = SYSTEM_CLOCK
	) {
		this.identity = data.id
		this.hostWhitelist = Object.freeze([...data.hostWhitelist])
		this.deadlineMs = data.expiresAt * 1000
		this.onExpire = onExpire
		this.clock = clock
		this.arm()
	}

	assertActive() {
		if(!this.isActive()) {
			throw authExpiredError()
		}
	}

	isActive() {
		if(this.disposed) {
			return false
		}
		if(this.clock.nowMs() < this.deadlineMs) {
			return true
		}
		this.expire()
		return false
	}

	dispose() {
		if(this.disposed) return
		this.disposed = true
		if(this.timer !== undefined) this.clock.clearTimeout(this.timer)
		this.timer = undefined
	}

	private arm() {
		if(this.disposed) return
		const remainingMs = this.deadlineMs - this.clock.nowMs()
		if(remainingMs <= 0) {
			this.expire()
			return
		}
		this.timer = this.clock.setTimeout(
			() => {
				this.timer = undefined
				this.arm()
			},
			Math.min(remainingMs, MAX_TIMEOUT_MS)
		)
	}

	private expire() {
		if(this.disposed) return
		this.dispose()
		this.onExpire()
	}
}
