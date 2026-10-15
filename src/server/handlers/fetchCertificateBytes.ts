import { refuseCertificateFetch } from '#src/server/utils/certificate-fetch.ts'
import type { RPCHandler } from '#src/types/handlers.ts'

export const fetchCertificateBytes: RPCHandler<'fetchCertificateBytes'> = async() => ({
	bytes: await refuseCertificateFetch()
})
