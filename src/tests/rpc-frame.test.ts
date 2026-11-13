import assert from 'node:assert/strict'
import { it } from 'node:test'

import { RPCMessage, RPCMessages } from '#src/proto/api.ts'
import { decodeRpcFrame, InvalidRpcFrameError, MAX_RPC_MESSAGES_PER_FRAME } from '#src/utils/rpc-frame.ts'

function frame(count: number) {
	return RPCMessages.encode(RPCMessages.create({ messages: Array.from({ length: count }, (_, id) => ({ id, createTunnelResponse: {} })) })).finish()
}

it('admits a full 32-message batch, but rejects entry 33 before either decoder runs', t => {
	assert.equal(decodeRpcFrame(frame(MAX_RPC_MESSAGES_PER_FRAME)).messages.length, MAX_RPC_MESSAGES_PER_FRAME)
	const oversized = frame(MAX_RPC_MESSAGES_PER_FRAME + 1)
	const envelope = t.mock.method(RPCMessages, 'decode')
	const entry = t.mock.method(RPCMessage, 'decode')
	assert.throws(() => decodeRpcFrame(oversized), InvalidRpcFrameError)
	assert.equal(envelope.mock.callCount(), 0)
	assert.equal(entry.mock.callCount(), 0)
})

it('rejects millions of empty entries without allocating decoded objects', t => {
	const envelope = t.mock.method(RPCMessages, 'decode')
	const entry = t.mock.method(RPCMessage, 'decode')
	for(const bytes of [64 * 1024, 4 * 1024 * 1024, 64 * 1024 * 1024]) {
		const flood = Buffer.alloc(bytes, Buffer.from([10, 0]))
		assert.throws(() => decodeRpcFrame(flood), InvalidRpcFrameError)
	}
	assert.equal(envelope.mock.callCount(), 0)
	assert.equal(entry.mock.callCount(), 0)
})

it('rejects empty, unknown-only, ambiguous and malformed entries before decoding', t => {
	const envelope = t.mock.method(RPCMessages, 'decode')
	for(const bytes of [
		[], [10, 0], [10, 2, 8, 1], // empty envelope, empty entry, ID only
		[10, 3, 208, 1, 0], // unknown field 26 only
		[10, 4, 58, 0, 74, 0], // two known payloads
		[10, 4, 58, 0, 58, 0], // duplicate known payload
		[10, 2, 56, 0], // wrong wire type for known payload
		[8, 0], [10], [10, 128], [10, 3, 58, 0], // wrong envelope type / truncation
		[0], [11, 12], [10, 2, 11, 12], // zero tag / groups
		[10, 2, 58, 1], // nested length exceeds entry
		[10, 2, 58, 0, 0], // trailing invalid tag
	]) assert.throws(() => decodeRpcFrame(Uint8Array.from(bytes)), InvalidRpcFrameError)
	assert.equal(envelope.mock.callCount(), 0)
})

it('bounds unknown fields and keeps ordinary unknown fields compatible', () => {
	assert.equal(decodeRpcFrame(Uint8Array.from([16, 1, 10, 5, 58, 0, 208, 1, 0])).messages.length, 1)
	assert.throws(() => decodeRpcFrame(Buffer.concat([Buffer.alloc(130, Buffer.from([16, 1])), frame(1)])), InvalidRpcFrameError)
	const body = Buffer.concat([Buffer.from([58, 0]), Buffer.alloc(192, Buffer.from([208, 1, 0]))])
	assert.throws(() => decodeRpcFrame(Buffer.concat([Buffer.from([10, 194, 1]), body])), InvalidRpcFrameError)
})

it('keeps large byte payloads and all known message variants compatible', () => {
	for(let field = 2; field <= 25; field++) {
		const tag = field * 8 + 2
		const encodedTag = tag < 128 ? [tag] : [tag & 127 | 128, tag >>> 7]
		const entry = [...encodedTag, 0]
		assert.equal(decodeRpcFrame(Uint8Array.from([10, entry.length, ...entry])).messages.length, 1)
	}
	const bytes = RPCMessages.encode(RPCMessages.create({ messages: [{ tunnelMessage: { tunnelId: 1, message: new Uint8Array(1024 * 1024) } }] })).finish()
	assert.equal(decodeRpcFrame(bytes).messages[0].tunnelMessage?.message.length, 1024 * 1024)
})
