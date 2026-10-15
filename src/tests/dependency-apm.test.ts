import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { it, mock } from 'node:test'

const starts: Record<string, unknown>[] = []
mock.module('elastic-apm-node', {
	defaultExport: {
		start(options: Record<string, unknown>) {
			starts.push(options)
			return { stop() {} }
		}
	}
})
const { getApm } = await import('#src/server/utils/apm.ts')

it('keeps upgraded APM disabled without both inputs and disables HTTP, header, and body capture', () => {
	const oldUrl = process.env.ELASTIC_APM_SERVER_URL
	const oldToken = process.env.ELASTIC_APM_SECRET_TOKEN
	try {
		process.env.ELASTIC_APM_SERVER_URL = 'http://127.0.0.1:1'
		delete process.env.ELASTIC_APM_SECRET_TOKEN
		assert.equal(getApm(), undefined)
		assert.equal(starts.length, 0)
		process.env.ELASTIC_APM_SECRET_TOKEN = randomBytes(24).toString('hex')
		const agent = getApm()
		assert.ok(agent)
		assert.equal(getApm(), agent)
		assert.equal(starts.length, 1)
		const options = starts[0]
		assert.equal(options.instrumentIncomingHTTPRequests, false)
		assert.equal(options.instrument, false)
		assert.equal(options.captureHeaders, false)
		assert.equal(options.captureBody, 'off')
	} finally {
		if(oldUrl === undefined) delete process.env.ELASTIC_APM_SERVER_URL
		else process.env.ELASTIC_APM_SERVER_URL = oldUrl
		if(oldToken === undefined) delete process.env.ELASTIC_APM_SECRET_TOKEN
		else process.env.ELASTIC_APM_SECRET_TOKEN = oldToken
	}
})
