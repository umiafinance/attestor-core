import type { Agent } from 'elastic-apm-node'
import ElasticAPM from 'elastic-apm-node'

import { getEnvVariable } from '#src/utils/env.ts'
import { logger } from '#src/utils/logger.ts'

let apm: Agent | undefined
let warnedUnsafeConfig = false
let reportedMissingConfig = false
const SAFE_APM_ENV_OVERRIDES = {
	ELASTIC_APM_CAPTURE_BODY: 'off',
	ELASTIC_APM_CAPTURE_ERROR_LOG_STACK_TRACES: 'messages',
	ELASTIC_APM_CAPTURE_EXCEPTIONS: 'false',
	ELASTIC_APM_CAPTURE_HEADERS: 'false',
	ELASTIC_APM_CENTRAL_CONFIG: 'false',
	ELASTIC_APM_INSTRUMENT: 'false',
	ELASTIC_APM_INSTRUMENT_INCOMING_HTTP_REQUESTS: 'false'
} as const

/**
 * Initialises the APM agent if required,
 * and returns it.
 * If ELASTIC_APM_SERVER_URL & ELASTIC_APM_SECRET_TOKEN
 * are not set will return undefined
 *
 * Utilises the standard env variables mentioned
 * here: https://www.elastic.co/guide/en/apm/agent/nodejs/current/custom-stack.html#custom-stack-advanced-configuration
 */
export function getApm(): Agent | undefined {
	if(
		!getEnvVariable('ELASTIC_APM_SERVER_URL')
		|| !getEnvVariable('ELASTIC_APM_SECRET_TOKEN')
	) {
		// Every RPC asks for the agent; one line per process is enough.
		if(!reportedMissingConfig) {
			logger.info(
				'ELASTIC_APM_SERVER_URL or ELASTIC_APM_SECRET_TOKEN not found'
				+ ' in env, APM agent not initialised'
			)
			reportedMissingConfig = true
		}

		return undefined
	}

	if(!apm) {
		// Elastic APM environment settings override start() options, so reject unsafe capture before starting it.
		const unsafeOverride = Object.entries(SAFE_APM_ENV_OVERRIDES)
			.some(([name, safeValue]) => {
				const value = getEnvVariable(name)
				return value !== undefined && value !== safeValue
			})
		if(unsafeOverride) {
			if(!warnedUnsafeConfig) logger.warn('APM configuration rejected')
			warnedUnsafeConfig = true
			return undefined
		}
		const sampleRate = +(
			getEnvVariable('ELASTIC_APM_SAMPLE_RATE')
			|| '0.1'
		)
		apm = ElasticAPM.start({
			serviceName: 'reclaim_attestor',
			serviceVersion: '4.0.0',
			transactionSampleRate: sampleRate,
			instrumentIncomingHTTPRequests: false,
			instrument: false,
			captureHeaders: false,
			captureBody: 'off',
			captureExceptions: false,
			captureErrorLogStackTraces: 'messages',
			centralConfig: false,
		})
		logger.info('initialised APM agent')
	}

	return apm
}
