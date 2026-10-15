import { makeTcpTunnel } from '#src/server/tunnels/make-tcp-tunnel.ts'
import { getApm } from '#src/server/utils/apm.ts'
import { resolveHostnames } from '#src/server/utils/dns.ts'
import { assertAuthenticatedTunnelHost } from '#src/server/utils/host-policy.ts'
import type { RPCHandler, Tunnel } from '#src/types/index.ts'
import { AttestorError } from '#src/utils/index.ts'
import { safeErrorCode } from '#src/utils/logger.ts'
import { rejection } from '#src/utils/rejection-reason.ts'

export const createTunnel: RPCHandler<'createTunnel'> = async(
	{ id, ...opts },
	{ tx, logger, client }
) => {
	if(client.tunnels[id]) {
		throw rejection('ERROR_BAD_REQUEST', 'TUNNEL_ID_IN_USE', `Tunnel "${id}" already exists`)
	}

	const allowedHosts = client.authHostWhitelist
	// Without AUTHENTICATION_PUBLIC_KEY, init admits sessions that have no host policy.
	if(allowedHosts === undefined) {
		throw rejection('ERROR_AUTHENTICATION_FAILED', 'AUTH_REQUIRED', 'Tunnels require an authenticated session')
	}

	assertAuthenticatedTunnelHost(allowedHosts, opts.host, opts.port)

	let cancelBgp: (() => void) | undefined

	const apm = getApm()
	const sessionTx = apm
		?.startTransaction('tunnelConnection', { childOf: tx })

	try {
		const tunnel = await makeTcpTunnel({
			...opts,
			logger,
			onMessage(message) {
				if(!client.isOpen) {
					logger.warn('client is closed, dropping message')
					return
				}

				if(!client.isAuthActive()) {
					return
				}

				void client.sendMessage({ tunnelMessage: { tunnelId: id, message } })
					.catch(err => {
						if(err instanceof AttestorError && err.code === 'ERROR_AUTHENTICATION_FAILED') return
						logger.error({ err }, 'failed to forward tunnel message')
					})
			},
			onClose(err) {
				cancelBgp?.()

				if(err) {
					sessionTx?.setLabel('errorCode', safeErrorCode(err))
					sessionTx?.setOutcome('failure')
				} else {
					sessionTx?.setOutcome('success')
				}

				sessionTx?.end()

				if(!client.isOpen) {
					return
				}
				if(!client.isAuthActive()) {
					return
				}

				client.sendMessage({
					tunnelDisconnectEvent: {
						tunnelId: id,
						error: err
							? AttestorError
								.fromError(err)
								.toProto()
							: undefined
					}
				})
					.catch(err => {
						logger.error(
							{ err },
							'failed to send tunnel disconnect event'
						)
					})
			},
		})

		try {
			await checkForBgp(tunnel)
		} catch(err) {
			logger.warn(
				{ err, host: opts.host },
				'failed to start BGP overlap check'
			)
		}

		try {
			client.assertAuthActive()
		} catch(err) {
			await tunnel.close(err)
			throw err
		}
		client.tunnels[id] = tunnel

		return {}
	} catch(err) {
		sessionTx?.setLabel('errorCode', safeErrorCode(err))
		sessionTx?.setOutcome('failure')
		sessionTx?.end()
		cancelBgp?.()

		throw err
	}

	async function checkForBgp(tunnel: Tunnel<unknown>) {
		if(!client.bgpListener) {
			return
		}

		// listen to all IPs for the host -- in case any of them
		// has a BGP announcement overlap, we'll close the tunnel
		// so the user can retry
		const ips = await resolveHostnames(opts.host)
		cancelBgp = client.bgpListener.onOverlap(ips, (info) => {
			logger.warn(
				{ info, host: opts.host },
				'BGP announcement overlap detected'
			)
			// track how many times we've seen a BGP overlap
			sessionTx?.addLabels({ bgpOverlap: true })

			void tunnel?.close(
				new AttestorError(
					'ERROR_BGP_ANNOUNCEMENT_OVERLAP',
					`BGP announcement overlap detected for ${opts.host}`,
				)
			)
		})

		logger.debug({ ips }, 'checking for BGP overlap')
	}
}
