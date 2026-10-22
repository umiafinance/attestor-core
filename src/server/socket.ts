import { randomUUID } from 'node:crypto'
import { promisify } from 'util'
import type { WebSocket as WS } from 'ws'

import { handleMessage } from '#src/client/utils/message-handler.ts'
import { DEFAULT_RPC_TIMEOUT_MS, INIT_TIMEOUT_MS, MAX_SOCKETS_PER_AUTH } from '#src/config/index.ts'
import type { AuthenticatedUserData, RPCMessage, TunnelMessage } from '#src/proto/api.ts'
import { HANDLERS } from '#src/server/handlers/index.ts'
import { AuthSession, authExpiredError } from '#src/server/utils/auth-session.ts'
import { getApm } from '#src/server/utils/apm.ts'
import { assertCanonicalHostWhitelist } from '#src/server/utils/host-policy.ts'
import { getInitialMessagesFromQuery } from '#src/server/utils/generics.ts'
import { recordRpc, recordTermination, trackTunnels, untrackTunnels } from '#src/server/utils/telemetry.ts'
import type { AcceptNewConnectionOpts, BGPListener, IAttestorServerSocket, Logger, RPCEvent, RPCHandler } from '#src/types/index.ts'
import { AttestorError, generateSessionId } from '#src/utils/index.ts'
import { AttestorSocket } from '#src/utils/socket-base.ts'
import { createServerLogRef, safeErrorCode, safeHandler, safeRpcStage } from '#src/utils/logger.ts'
import { rejection } from '#src/utils/rejection-reason.ts'

const openSocketsByAuth = new Map<string, number>()

/** Whether another socket may still init with this auth ID on this instance. */
export function hasAuthSocketCapacity(identity: string) {
	return (openSocketsByAuth.get(identity) ?? 0) < MAX_SOCKETS_PER_AUTH
}

export class AttestorServerSocket extends AttestorSocket implements IAttestorServerSocket {

	tunnels: IAttestorServerSocket['tunnels'] = {}
	readonly sessionId: number
	readonly bgpListener: BGPListener | undefined
	private authSession: AuthSession | undefined
	private connectionState: 'open' | 'terminating' | 'closed' = 'open'
	private readonly initDeadline: ReturnType<typeof setTimeout>
	private countedAuthIdentity: string | undefined

	private constructor(
		socket: WS,
		sessionId: number,
		bgpListener: BGPListener | undefined,
		logger: Logger
	) {
		// @ts-ignore
		super(socket, {}, logger)

		this.sessionId = sessionId
		this.bgpListener = bgpListener
		trackTunnels(this)

		// handle RPC requests
		this.addEventListener('rpc-request', handleRpcRequest.bind(this))
		// forward packets to the appropriate tunnel
		this.addEventListener('tunnel-message', handleTunnelMessage.bind(this))
		// close all tunnels when the connection is terminated
		// since this tunnel can no longer be written to
		this.addEventListener('connection-terminated', () => {
			const closeSocket = this.connectionState === 'open' && !this.isClosed
			this.closeResources()
			if(closeSocket) this.socket.close()
		})
		// Keep-alive pongs would hold a socket that never authenticates open indefinitely.
		this.initDeadline = setTimeout(() => {
			if(this.isInitialised) return
			const err = rejection('ERROR_TIMEOUT', 'INIT_TIMEOUT', 'Init not received in time')
			this.logger.warn({ err }, 'init deadline reached')
			recordTermination('INIT_TIMEOUT')
			void this.terminateConnection(err)
				.catch(terminateErr => this.logger.error({ err: terminateErr }, 'failed to terminate uninitialised socket'))
		}, INIT_TIMEOUT_MS)
		this.initDeadline.unref?.()
	}

	private closeResources() {
		if(this.connectionState === 'closed') return
		this.connectionState = 'closed'
		untrackTunnels(this)
		clearTimeout(this.initDeadline)
		this.releaseAuthSlot()
		this.authSession?.dispose()
		for(const tunnelId in this.tunnels) {
			const tunnel = this.tunnels[tunnelId]
			delete this.tunnels[tunnelId]
			try {
				void Promise.resolve(tunnel.close(new Error('WS session terminated')))
					.catch(err => this.logger.warn({ err }, 'failed to close tunnel'))
			} catch(err) {
				this.logger.warn({ err }, 'failed to close tunnel')
			}
		}
	}

	override async terminateConnection(err?: Error) {
		if(this.connectionState !== 'open') return
		this.connectionState = 'terminating'
		try {
			await super.terminateConnection(err)
		} finally {
			this.closeResources()
		}
	}

	get authIdentity() {
		return this.authSession?.identity
	}

	get authHostWhitelist() {
		return this.authSession?.hostWhitelist
	}

	setAuthSession(data: AuthenticatedUserData) {
		if(this.authSession) throw AttestorError.badRequest('Auth session already set')
		assertCanonicalHostWhitelist(data.hostWhitelist)
		if(this.connectionState !== 'open') throw authExpiredError()
		if(!hasAuthSocketCapacity(data.id)) {
			throw rejection('ERROR_AUTHENTICATION_FAILED', 'AUTH_SOCKET_LIMIT', 'Too many open sockets for this auth')
		}
		openSocketsByAuth.set(data.id, (openSocketsByAuth.get(data.id) ?? 0) + 1)
		this.countedAuthIdentity = data.id
		this.authSession = new AuthSession(
			data,
			() => {
				this.logger.warn('auth expired')
				recordTermination('AUTH_EXPIRED')
				void this.terminateConnection(authExpiredError())
					.catch(err => this.logger.error({ err }, 'failed to terminate expired auth session'))
			}
		)
		this.assertAuthActive()
	}

	private releaseAuthSlot() {
		const identity = this.countedAuthIdentity
		if(identity === undefined) return
		this.countedAuthIdentity = undefined
		const open = (openSocketsByAuth.get(identity) ?? 1) - 1
		if(open > 0) openSocketsByAuth.set(identity, open)
		else openSocketsByAuth.delete(identity)
	}

	assertAuthActive() {
		if(this.connectionState !== 'open') throw authExpiredError()
		this.authSession?.assertActive()
	}

	isAuthActive() {
		return this.connectionState === 'open' && (this.authSession?.isActive() ?? false)
	}

	protected override assertCanProcessMessage() {
		this.assertAuthActive()
	}

	protected override assertCanSendMessage(msgs: Partial<RPCMessage>[]) {
		if(msgs.length === 1 && msgs[0].connectionTerminationAlert) return
		this.assertAuthActive()
	}

	getTunnel(tunnelId: number) {
		const tunnel = this.tunnels[tunnelId]
		if(!tunnel) {
			throw rejection('ERROR_NOT_FOUND', 'TUNNEL_NOT_FOUND', `Tunnel "${tunnelId}" not found`)
		}

		return tunnel
	}

	removeTunnel(tunnelId: TunnelMessage['tunnelId']): void {
		delete this.tunnels[tunnelId]
	}

	static async acceptConnection(
		socket: WS,
		{ req, logger, bgpListener }: AcceptNewConnectionOpts
	) {
		// promisify ws.send -- so the sendMessage method correctly
		// awaits the send operation
		const bindSend = socket.send.bind(socket)
		socket.send = promisify(bindSend)

		const sessionId = generateSessionId()
		logger = logger.child({ connectionRef: createServerLogRef(randomUUID) })

		const client = new AttestorServerSocket(
			socket, sessionId, bgpListener, logger
		)
		try {
			const initMsgs = getInitialMessagesFromQuery(req)
			logger.trace(
				{ initMsgs: initMsgs.length },
				'new connection, validating...'
			)
			for(const msg of initMsgs) {
				await handleMessage.call(client, msg)
			}

			logger.debug('connection accepted')
		} catch(err) {
			logger.error({ err }, 'error in new connection')
			if(client.isOpen) {
				await client.terminateConnection(
					err instanceof AttestorError
						? err
						: AttestorError.badRequest(err.message)
				)
			}

			return
		}

		return client
	}
}

async function handleTunnelMessage(
	this: IAttestorServerSocket,
	{ data: { tunnelId, message } }: RPCEvent<'tunnel-message'>
) {
	try {
		this.assertAuthActive()
		const tunnel = this.getTunnel(tunnelId)
		await tunnel.write(message)
	} catch(err) {
		this.logger?.error({ err, tunnelId }, 'error writing to tunnel')
	}
}

async function handleRpcRequest(
	this: IAttestorServerSocket,
	{ data: { data, requestId, respond, type } }: RPCEvent<'rpc-request'>
) {
	const logger = this.logger.child({ handler: safeHandler(type), operationRef: createServerLogRef(randomUUID) })
	const startedAt = Date.now()

	const apm = getApm()
	const tx = apm?.startTransaction('rpc')
	tx?.setLabel('stage', safeRpcStage(type))

	const timeout = setTimeout(() => {
		logger.warn('RPC took too long to respond')
	}, DEFAULT_RPC_TIMEOUT_MS)

	try {
		this.assertAuthActive()
		logger.debug({ data }, 'handling RPC request')

		const handler = HANDLERS[type] as RPCHandler<typeof type>
		const res = await handler(data, { client: this, logger, tx })
		this.assertAuthActive()
		// Observe send failures when expiry suppresses a response.
		await respond(res)

		const durationMs = Date.now() - startedAt
		logger.info({ durationMs }, 'handled RPC request')
		recordRpc(type, durationMs, 'success')
		tx?.setOutcome('success')
	} catch(err) {
		const durationMs = Date.now() - startedAt
		logger.error({ err, durationMs }, 'error in RPC request')
		recordRpc(type, durationMs, 'failure', err)
		try {
			await respond(AttestorError.fromError(err))
		} catch(sendErr) {
			if(!(sendErr instanceof AttestorError && sendErr.code === 'ERROR_AUTHENTICATION_FAILED')) {
				logger.warn('failed to deliver RPC error response')
			}
		}
		tx?.setOutcome('failure')

		tx?.setLabel('errorCode', safeErrorCode(err))
	} finally {
		clearTimeout(timeout)
		tx?.end()
	}
}
