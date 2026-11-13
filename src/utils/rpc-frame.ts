import { BinaryReader } from '@bufbuild/protobuf/wire'

import { RPCMessages } from '#src/proto/api.ts'
import { AttestorError } from '#src/utils/error.ts'

export const MAX_RPC_MESSAGES_PER_FRAME = 32
const MAX_FIELDS_PER_ENVELOPE = 64
const MAX_FIELDS_PER_MESSAGE = 64

export class InvalidRpcFrameError extends AttestorError {
	constructor() {
		super('ERROR_BAD_REQUEST', 'Invalid RPC frame')
	}
}

/** Validate the wire envelope before the generated decoder allocates any RPC objects. */
export function decodeRpcFrame(bytes: Uint8Array): RPCMessages {
	try {
		// Count first, skipping bodies. Even millions of empty entries stop at entry 33.
		scanEnvelope(bytes, false)
		// Validate every entry before dispatching any part of the batch.
		scanEnvelope(bytes, true)
		return RPCMessages.decode(bytes)
	} catch {
		// Never retain or log attacker-controlled bytes or decoder error text.
		throw new InvalidRpcFrameError()
	}
}

function scanEnvelope(bytes: Uint8Array, validateMessages: boolean): void {
	const reader = new BinaryReader(bytes)
	let messages = 0
	let fields = 0
	while(reader.pos < reader.len) {
		if(++fields > MAX_FIELDS_PER_ENVELOPE) throw new InvalidRpcFrameError()
		const tag = reader.uint32()
		if(tag >>> 3 === 1) {
			if((tag & 7) !== 2 || ++messages > MAX_RPC_MESSAGES_PER_FRAME) {
				throw new InvalidRpcFrameError()
			}
			const size = reader.uint32()
			const end = reader.pos + size
			if(end > reader.len) throw new InvalidRpcFrameError()
			if(validateMessages) validateMessage(bytes.subarray(reader.pos, end))
			reader.pos = end
		} else {
			skipField(reader, tag)
		}
	}
	if(messages === 0) throw new InvalidRpcFrameError()
}

function validateMessage(bytes: Uint8Array): void {
	const reader = new BinaryReader(bytes)
	let fields = 0
	let payloads = 0
	while(reader.pos < reader.len) {
		if(++fields > MAX_FIELDS_PER_MESSAGE) throw new InvalidRpcFrameError()
		const tag = reader.uint32()
		const field = tag >>> 3
		// RPCMessage's oneof occupies fields 2..25 in the pinned proto/api.proto.
		// Empty response bodies are valid; an empty RPCMessage is not.
		if(field >= 2 && field <= 25) {
			if((tag & 7) !== 2 || ++payloads > 1) throw new InvalidRpcFrameError()
		} else if(field === 1 && (tag & 7) !== 0) {
			throw new InvalidRpcFrameError()
		}
		skipField(reader, tag)
	}
	if(payloads !== 1) throw new InvalidRpcFrameError()
}

function skipField(reader: BinaryReader, tag: number): void {
	const wireType = tag & 7
	// No groups exist in this proto3 protocol; reject them without recursive skipping.
	if(tag >>> 3 === 0 || ![0, 1, 2, 5].includes(wireType)) throw new InvalidRpcFrameError()
	reader.skip(wireType)
	if(reader.pos > reader.len) throw new InvalidRpcFrameError()
}
