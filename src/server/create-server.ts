import type { IncomingMessage } from 'http'
import { createServer as createHttpServer } from 'http'
import serveStatic from 'serve-static'
import type { Duplex } from 'stream'
import type { WebSocket } from 'ws'
import { WebSocketServer } from 'ws'

import {
	API_SERVER_PORT,
	ATTESTOR_ADDRESS_PATHNAME,
	BROWSER_RPC_PATHNAME,
	MAX_AUTHENTICATED_WS_PAYLOAD_BYTES,
	MAX_PRE_AUTH_WS_PAYLOAD_BYTES,
	WS_PATHNAME
} from '#src/config/index.ts'
import { AttestorServerSocket, hasAuthSocketCapacity } from '#src/server/socket.ts'
import { getAttestorAddress, getInitialMessagesFromQuery } from '#src/server/utils/generics.ts'
import { addKeepAlive } from '#src/server/utils/keep-alive.ts'
import type { BGPListener } from '#src/types/index.ts'
import { createBgpListener } from '#src/utils/bgp-listener.ts'
import { assertValidAuthRequest } from '#src/utils/auth.ts'
import { getEnvVariable } from '#src/utils/env.ts'
import { logger as LOGGER } from '#src/utils/index.ts'
import { SelectedServiceSignatureType } from '#src/utils/signatures/index.ts'
import { promisifySend } from '#src/utils/ws.ts'

const PORT = +(getEnvVariable('PORT') || API_SERVER_PORT)
const DISABLE_BGP_CHECKS = getEnvVariable('DISABLE_BGP_CHECKS') === '1'

const ATTESTOR_ADDRESS_JSON_RES = JSON.stringify({
	address: getAttestorAddress(SelectedServiceSignatureType),
	signatureType: SelectedServiceSignatureType
})

/**
 * Creates the WebSocket API server,
 * creates a fileserver to serve the browser RPC client,
 * and listens on the given port.
 */
export async function createServer(port = PORT) {
	const http = createHttpServer()
	const serveBrowserRpc = serveStatic(
		'browser',
		{
			index: ['index.html'],
			setHeaders(res) {
				res.setHeader('Access-Control-Allow-Origin', '*')
			},
		}
	)
	const bgpListener = !DISABLE_BGP_CHECKS
		? createBgpListener(LOGGER.child({ service: 'bgp-listener' }))
		: undefined

	const wss = new WebSocketServer({
		noServer: true,
		maxPayload: MAX_AUTHENTICATED_WS_PAYLOAD_BYTES,
		perMessageDeflate: false,
	})
	const preAuthWss = new WebSocketServer({ noServer: true, maxPayload: MAX_PRE_AUTH_WS_PAYLOAD_BYTES })
	http.on('upgrade', (request, socket, head) => {
		void handleUpgrade(wss, preAuthWss, request, socket, head)
	})
	http.on('request', (req, res) => {
		const url = URL.parse(req.url || '', 'http://localhost')
		if(!url) {
			res.statusCode = 422
			res.end('Invalid URL')
			return
		}

		if(url.pathname === ATTESTOR_ADDRESS_PATHNAME) {
			res.writeHead(200, { 'Content-Type': 'application/json' })
			res.end(ATTESTOR_ADDRESS_JSON_RES)
			return
		}

		// simple way to serve files at the browser RPC path
		if(!url.pathname?.startsWith(BROWSER_RPC_PATHNAME)) {
			res.statusCode = 404
			res.end('Not found')
			return
		}

		req.url = req.url!.slice(BROWSER_RPC_PATHNAME.length) || '/'

		serveBrowserRpc(req, res, (err) => {
			if(err) {
				LOGGER.error({ err, url: req.url }, 'Failed to serve file')
			}

			res.statusCode = err?.statusCode ?? 404
			res.end(err?.message ?? 'Not found')
		})
	})

	// wait for us to start listening
	http.listen(port)
	await new Promise<void>((resolve, reject) => {
		http.once('listening', () => resolve())
		http.once('error', reject)
	})

	wss.on('connection', (ws, req) => handleNewClient(ws, req, bgpListener))

	LOGGER.info(
		{
			port,
			apiPath: WS_PATHNAME,
			browserRpcPath: BROWSER_RPC_PATHNAME,
			signerAddress: getAttestorAddress(SelectedServiceSignatureType)
		},
		'WS server listening'
	)

	const wssClose = wss.close.bind(wss)
	wss.close = (cb) => {
		preAuthWss.close()
		wssClose(() => http.close(cb))
		bgpListener?.close()
	}

	return wss
}

async function handleNewClient(
	ws: WebSocket,
	req: IncomingMessage,
	bgpListener: BGPListener | undefined
) {
	promisifySend(ws)
	const client = await AttestorServerSocket.acceptConnection(
		ws,
		{ req, bgpListener, logger: LOGGER }
	)
	// if initialisation fails, don't store the client
	if(!client) {
		return
	}

	ws.serverSocket = client
	addKeepAlive(ws, LOGGER.child({ sessionId: client.sessionId }))
}

// Only a verified auth in the upgrade query, where the client sends init, admits claim-sized messages.
async function handleUpgrade(
	wss: WebSocketServer,
	preAuthWss: WebSocketServer,
	request: IncomingMessage,
	socket: Duplex,
	head: Buffer
) {
	const { pathname } = new URL(request.url!, 'wss://base.url')
	if(pathname !== WS_PATHNAME) {
		socket.destroy()
		return
	}

	const destroy = () => socket.destroy()
	socket.on('error', destroy)
	const server = await hasVerifiedQueryAuth(request) ? wss : preAuthWss
	socket.off('error', destroy)
	server.handleUpgrade(request, socket, head, (ws) => {
		wss.emit('connection', ws, request)
	})
}

async function hasVerifiedQueryAuth(request: IncomingMessage) {
	try {
		const init = getInitialMessagesFromQuery(request)[0]?.initRequest
		if(!init?.auth) return false
		await assertValidAuthRequest(init.auth, init.signatureType)
		return hasAuthSocketCapacity(init.auth.data!.id)
	} catch {
		return false
	}
}
