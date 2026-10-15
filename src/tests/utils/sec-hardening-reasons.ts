/** Reasons added by the sec-hardening layer; sec-hardening.test.ts exercises each. */
export const SEC_HARDENING_REASONS: readonly string[] = [
	'AUTH_LIFETIME_INVALID',
	'INIT_TIMEOUT',
	'CERTIFICATE_FETCH_DISABLED',
	'TOPRF_DISABLED',
	'AUTH_SOCKET_LIMIT'
]
