import { rejection } from '#src/utils/rejection-reason.ts'

/** The issuer URL comes from the client or a peer certificate; reviewed provider hosts send complete chains. */
export async function refuseCertificateFetch(): Promise<Uint8Array> {
	throw rejection('ERROR_CERTIFICATE_FETCH_FAILED', 'CERTIFICATE_FETCH_DISABLED', 'Certificate fetching is disabled')
}
