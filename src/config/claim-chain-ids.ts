import { CHAIN_ID } from '#src/utils/chain-id.ts'

/** Chains whose auction and sandbox context messages this server signs; CLAIM_EPOCH must be registered on each. */
export function parseClaimChainIds(raw: string | undefined): readonly string[] {
	const ids = raw === undefined ? [] : raw.split(',')
	const canonical = ids.length > 0 && ids.every((id, index) => CHAIN_ID.test(id)
		&& Number.isSafeInteger(Number(id))
		&& (index === 0 || Number(ids[index - 1]) < Number(id)))
	if(!canonical) {
		throw new Error('CLAIM_CHAIN_IDS must be strictly ascending comma-separated canonical decimal chain IDs')
	}

	return Object.freeze(ids)
}

export const CLAIM_CHAIN_IDS = parseClaimChainIds(process.env.CLAIM_CHAIN_IDS)
