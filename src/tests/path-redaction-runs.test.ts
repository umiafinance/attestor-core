import assert from 'node:assert'
import { it } from 'node:test'

import { assertNoSmuggle } from '#src/providers/http/index.ts'
import { REDACTION_CHAR, strToUint8Array } from '#src/utils/index.ts'

const PARAMS = {
	url: 'https://prod-api.fomo.family/v2/users/{{id}}',
	method: 'GET',
	responseMatches: [],
	responseRedactions: [],
} as const

function request(path: string) {
	return strToUint8Array(
		`GET ${path} HTTP/1.1\r\n`
		+ 'Host: prod-api.fomo.family\r\n'
		+ 'Connection: close\r\n\r\n'
	)
}

const hidden = (length: number) => REDACTION_CHAR.repeat(length)

it('allows a hidden UUID whose groups are separated by visible hyphens', () => {
	const path = `/v2/users/${[8, 4, 4, 4, 12].map(hidden).join('-')}`
	assert.doesNotThrow(() => assertNoSmuggle(request(path), PARAMS))
})

it('allows the upstream limit of twelve consecutive redactions', () => {
	assert.doesNotThrow(() => assertNoSmuggle(request(`/v2/users/${hidden(12)}`), PARAMS))
})

it('rejects a run long enough to end the request line', () => {
	assert.throws(
		() => assertNoSmuggle(request(`/v2/users/${hidden(13)}`), PARAMS),
		{ message: 'Too many consecutive redactions in URL path: 13' }
	)
	assert.throws(
		() => assertNoSmuggle(request(`/v2/users/${hidden(5)}-${hidden(13)}-${hidden(2)}`), PARAMS),
		{ message: 'Too many consecutive redactions in URL path: 13' }
	)
})

it('still requires the signed method, host and connection headers', () => {
	assert.throws(
		() => assertNoSmuggle(request(`/v2/users/${hidden(8)}`), { ...PARAMS, method: 'POST' }),
		{ message: /Method\/Host mismatch/ }
	)
})
