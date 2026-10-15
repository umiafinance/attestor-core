import assert from 'node:assert/strict'
import { Writable } from 'node:stream'
import { it } from 'node:test'

import { getApm } from '#src/server/utils/apm.ts'
import { makeLogger } from '#src/utils/logger.ts'

it('keeps actual APM manual telemetry without an uncaught-error capture handler', async() => {
	const safeEnv = {
		ELASTIC_APM_SERVER_URL: 'http://127.0.0.1:1',
		ELASTIC_APM_SECRET_TOKEN: 'synthetic-test-token',
		ELASTIC_APM_SAMPLE_RATE: '1',
		ELASTIC_APM_CAPTURE_BODY: 'off',
		ELASTIC_APM_CAPTURE_ERROR_LOG_STACK_TRACES: 'messages',
		ELASTIC_APM_CAPTURE_EXCEPTIONS: 'false',
		ELASTIC_APM_CAPTURE_HEADERS: 'false',
		ELASTIC_APM_CENTRAL_CONFIG: 'false',
		ELASTIC_APM_INSTRUMENT: 'false',
		ELASTIC_APM_INSTRUMENT_INCOMING_HTTP_REQUESTS: 'false'
	}
	const unsafeEnv = {
		ELASTIC_APM_CAPTURE_BODY: 'all',
		ELASTIC_APM_CAPTURE_ERROR_LOG_STACK_TRACES: 'always',
		ELASTIC_APM_CAPTURE_EXCEPTIONS: 'true',
		ELASTIC_APM_CAPTURE_HEADERS: 'true',
		ELASTIC_APM_CENTRAL_CONFIG: 'true',
		ELASTIC_APM_INSTRUMENT: 'true',
		ELASTIC_APM_INSTRUMENT_INCOMING_HTTP_REQUESTS: 'true'
	}
	const names = Object.keys(safeEnv)
	const previous = Object.fromEntries(names.map(name => [name, process.env[name]]))
	const beforeListeners = process.listeners('uncaughtException')
	const lines: string[] = []
	makeLogger(false, 'info', undefined, new Writable({ write(chunk, _encoding, done) { lines.push(chunk.toString()); done() } }))
	for(const [name, value] of Object.entries(safeEnv)) process.env[name] = value
	let agent: ReturnType<typeof getApm> | undefined
	try {
		for(const [name, value] of Object.entries(unsafeEnv)) {
			process.env[name] = value
			assert.equal(getApm(), undefined)
			assert.deepEqual(process.listeners('uncaughtException'), beforeListeners)
			process.env[name] = safeEnv[name as keyof typeof safeEnv]
		}
		const rejected = lines.map(line => JSON.parse(line) as Record<string, unknown>)
		assert.ok(rejected.some(record => record.stage === 'connection' && record.outcome === 'failure'))
		assert.ok(rejected.every(record => record.msg === 'attestor diagnostic'))
		agent = getApm()
		assert.ok(agent)
		const active = agent as typeof agent & { _conf: Record<string, unknown>, _uncaughtExceptionListener: unknown }
		assert.equal(active._conf.captureExceptions, false)
		assert.equal(active._conf.captureErrorLogStackTraces, 'messages')
		assert.equal(active._conf.captureHeaders, false)
		assert.equal(active._conf.captureBody, 'off')
		assert.equal(active._conf.centralConfig, false)
		assert.equal(active._conf.instrument, false)
		assert.equal(active._conf.instrumentIncomingHTTPRequests, false)
		assert.equal(active._uncaughtExceptionListener, null)
		assert.deepEqual(process.listeners('uncaughtException'), beforeListeners)
		const tx = agent.startTransaction('rpc')
		assert.ok(tx)
		assert.equal(tx.setLabel('stage', 'rpc'), true)
		assert.equal(tx.setLabel('errorCode', 'INTERNAL_ERROR'), true)
		assert.deepEqual((tx as typeof tx & { _labels: Record<string, unknown> })._labels, { stage: 'rpc', errorCode: 'INTERNAL_ERROR' })
		tx.setOutcome('failure')
		tx.end()
	} finally {
		await agent?.destroy()
		makeLogger(false, 'info')
		for(const name of names) {
			const value = previous[name]
			if(value === undefined) delete process.env[name]
			else process.env[name] = value
		}
	}
})
