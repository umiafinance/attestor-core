import type { RPCHandler } from '#src/types/index.ts'
import { rejection } from '#src/utils/rejection-reason.ts'

// Signed TEE outputs do not bind the raw destination host, port, or SNI.
export const claimTeeBundle: RPCHandler<'claimTeeBundle'> = async() => {
	throw rejection('ERROR_BAD_REQUEST', 'TEE_CLAIMS_DISABLED', 'TEE claims require verified endpoint binding')
}
