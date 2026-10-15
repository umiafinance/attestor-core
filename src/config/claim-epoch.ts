/** The server signs claims for exactly one configured uint32 witness epoch. */
export function parseClaimEpoch(raw: string | undefined): number {
	const epoch = Number(raw)
	if(!raw || !/^[1-9][0-9]*$/.test(raw) || epoch > 4294967295) {
		throw new Error('CLAIM_EPOCH must be a canonical decimal uint32 from 1 to 4294967295')
	}

	return epoch
}

export const CLAIM_EPOCH = parseClaimEpoch(process.env.CLAIM_EPOCH)
