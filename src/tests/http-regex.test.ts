import assert from 'node:assert/strict'
import { it, mock } from 'node:test'

mock.module('re2', { defaultExport: undefined })

it('refuses to load the HTTP provider when RE2 is unavailable', async() => {
	await assert.rejects(import('#src/providers/http/utils.ts'), /RE2 is required/)
})
