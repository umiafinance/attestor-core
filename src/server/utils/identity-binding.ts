import type { InitRequest } from '#src/proto/api.ts'
import { providers } from '#src/providers/index.ts'
import { niceParseJsonObject } from '#src/server/utils/generics.ts'
import type { IDecryptedTranscript, Logger, ProviderParams } from '#src/types/index.ts'
import { extractApplicationDataFromTranscript, REDACTION_CHAR } from '#src/utils/index.ts'
import { rejection, withRejectionReason } from '#src/utils/rejection-reason.ts'

const CAPTURE_NAME = /\(\?<(?![=!])([^>]*)>/g
const PLACEHOLDER = /\{\{([^{}]+)\}\}/g

type HttpParams = ProviderParams<'http'>
type IdentityCapture = { key: string, regex: string }

/**
 * Every oprf-raw capture of the recipe must be signed as the nullifier of its whole revealed value,
 * read from the response before replacement, with exactly one marker per capture. The other signed
 * keys must be values the recipe can produce; secret templates never are.
 */
export async function assertRecipeBoundIdentity(
	parameters: string,
	signedContext: string,
	decrypted: IDecryptedTranscript,
	metadata: InitRequest,
	logger: Logger
) {
	const params: HttpParams = niceParseJsonObject(parameters, 'params')
	// Their template values reach extractedParameters, yet nothing compares them to the tunnel.
	if(params.geoLocation || params.proxySessionId) {
		throw rejection('ERROR_BAD_REQUEST', 'PROVIDER_PARAMS_INVALID', 'Claim parameters cannot route the request')
	}

	const identity = recipeIdentityCaptures(params)
	const extracted: { [key: string]: unknown } = niceParseJsonObject(signedContext, 'context')
		.extractedParameters ?? {}
	const signable = recipeSignedKeys(params, identity)
	for(const key of Object.keys(extracted)) {
		if(!signable.has(key) || key.toLowerCase().includes('secret')) {
			throw unbound(`Extracted parameter ${key} is not a value the recipe produces`)
		}
	}

	const replacements = decrypted.oprfRawReplacements ?? []
	if(replacements.length !== identity.length) {
		throw unbound(`Expected ${identity.length} oprf-raw markers for the recipe identity captures, got ${replacements.length}`)
	}

	if(!identity.length) {
		return
	}

	let captures: { [key: string]: string }
	try {
		const result = await providers.http.assertValidProviderReceipt({
			clientVersion: metadata.clientVersion,
			receipt: extractApplicationDataFromTranscript({ ...decrypted, transcript: decrypted.originalTranscript }),
			params: {
				...params,
				responseMatches: identity.map(({ regex }) => ({ type: 'regex' as const, value: regex }))
			},
			logger,
			ctx: { version: metadata.clientVersion }
		})
		captures = result?.extractedParameters ?? {}
	} catch(err) {
		throw withRejectionReason(err, 'SIGNED_CONTEXT_INVALID', 'ERROR_BAD_REQUEST')
	}

	const unmatched = [...replacements]
	for(const { key } of identity) {
		const capture = captures[key]
		if(!capture) {
			throw unbound(`Recipe capture ${key} is absent from the response`)
		}

		// Undisclosed bytes are revealed as the redaction character; hashing them splits the account.
		if(capture.includes(REDACTION_CHAR)) {
			throw unbound(`Recipe capture ${key} is not fully revealed`)
		}

		const index = unmatched.findIndex(({ originalText, nullifierText }) => (
			originalText === capture && nullifierText === extracted[key]
		))
		if(index < 0) {
			throw unbound(`Identity ${key} is not the nullifier of its whole recipe capture`)
		}

		unmatched.splice(index, 1)
	}
}

function recipeIdentityCaptures(params: HttpParams) {
	const captures: IdentityCapture[] = []
	for(const { hash, regex, xPath, jsonPath } of params.responseRedactions ?? []) {
		if(!hash) {
			continue
		}

		const names = regex ? [...regex.matchAll(CAPTURE_NAME)].map(match => match[1]) : []
		if(hash !== 'oprf-raw' || names.length !== 1) {
			throw unbound('Hashed redactions must be one oprf-raw regex capture each')
		}

		// A redacted body cannot establish a selector's scope, so the regex must anchor the value itself.
		if(xPath || jsonPath) {
			throw unbound(`Identity capture ${names[0]} cannot be scoped by xPath or jsonPath`)
		}

		if(captures.some(({ key }) => key === names[0])) {
			throw unbound(`Recipe captures ${names[0]} more than once`)
		}

		captures.push({ key: names[0], regex: regex! })
	}

	return captures
}

/** Keys the HTTP provider can sign for this recipe: identity captures, public templates and match captures. */
function recipeSignedKeys(params: HttpParams, identity: IdentityCapture[]) {
	const keys = new Set(identity.map(({ key }) => key))
	const templates = [params.url, typeof params.body === 'string' ? params.body : undefined]
	for(const { type, value } of params.responseMatches ?? []) {
		templates.push(value)
		if(type === 'regex') {
			for(const [, name] of value.matchAll(CAPTURE_NAME)) {
				keys.add(name)
			}
		}
	}

	for(const template of templates) {
		for(const [, name] of template?.matchAll(PLACEHOLDER) ?? []) {
			keys.add(name)
		}
	}

	return keys
}

function unbound(message: string) {
	return rejection('ERROR_BAD_REQUEST', 'SIGNED_CONTEXT_INVALID', message)
}
