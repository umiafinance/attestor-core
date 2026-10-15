import type { RPCHandler } from '#src/types/index.ts'
import { rejection } from '#src/utils/rejection-reason.ts'

// Unlimited OPRF on client input lets anyone link handles to on-chain nullifiers; oprf-raw runs inside claimTunnel.
export const toprf: RPCHandler<'toprf'> = async() => {
	throw rejection('ERROR_BAD_REQUEST', 'TOPRF_DISABLED', 'TOPRF requests are disabled')
}
