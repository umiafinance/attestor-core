import { Address4, Address6 } from 'ip-address'
import type { Logger } from 'pino'

import { BGP_WS_URL } from '#src/config/index.ts'
import type { BGPAnnouncementOverlapData, BGPListener } from '#src/types/index.ts'
import { BGP_EVENTS } from '#src/utils/diagnostic-events.ts'
import { makeWebSocket } from '#src/utils/ws.ts'

const ANNOUNCEMENT_OVERLAP = 'announcement-overlap'
const RECONNECT_MIN_MS = 1_000
const RECONNECT_MAX_MS = 30_000

class BGPAnnouncementOverlapEvent extends Event {

	readonly data: BGPAnnouncementOverlapData

	constructor(data: BGPAnnouncementOverlapData) {
		super(ANNOUNCEMENT_OVERLAP)
		this.data = data
	}
}

/**
 * Listens for BGP announcements and emits events whenever
 * an announcement overlaps with a target IP.
 */
export function createBgpListener(logger: Logger): BGPListener {
	let ws: ReturnType<typeof makeWebSocket> | undefined
	let closed = false
	let reconnectTimer: ReturnType<typeof setTimeout> | undefined
	let reconnectDelay = RECONNECT_MIN_MS

	const targetIps = new Set<string>()
	const eventTarget = new EventTarget()

	openWs()

	return {
		onOverlap(ips, callback) {
			for(const ip of ips) {
				targetIps.add(ip)
			}

			eventTarget.addEventListener(
				ANNOUNCEMENT_OVERLAP,
				_callback
			)

			return () => {
				for(const ip of ips) {
					targetIps.delete(ip)
				}

				eventTarget.removeEventListener(
					ANNOUNCEMENT_OVERLAP,
					_callback
				)
			}

			function _callback(event: BGPAnnouncementOverlapEvent) {
				callback(event.data)
			}
		},
		close() {
			// Invalidate callbacks before closing; close/error may already be queued.
			closed = true
			clearTimeout(reconnectTimer)
			reconnectTimer = undefined
			const socket = ws
			ws = undefined
			if(socket) retire(socket)
		}
	}

	function openWs(): void {
		if(closed) return
		logger.debug({ event: BGP_EVENTS.connecting })

		let socket: ReturnType<typeof makeWebSocket>
		try {
			socket = makeWebSocket(BGP_WS_URL)
		} catch(err) {
			logger.warn({ event: BGP_EVENTS.connectFailed, err })
			scheduleReconnect()
			return
		}

		ws = socket
		socket.onopen = () => {
			if(!isCurrent()) return
			// Always send through the socket that owns this callback.
			if(socket.readyState !== WebSocket.OPEN) {
				logger.warn({ event: BGP_EVENTS.notOpen })
				onClose()
				return
			}

			try {
				socket.send(JSON.stringify({ type: 'ris_subscribe', data: { type: 'UPDATE' } }))
			} catch(err) {
				logger.warn({ event: BGP_EVENTS.subscribeFailed, err })
				onClose()
				return
			}

			reconnectDelay = RECONNECT_MIN_MS
			logger.info({ event: BGP_EVENTS.connected })
		}
		socket.onerror = () => {
			if(!isCurrent()) return
			logger.warn({ event: BGP_EVENTS.connectionError })
			onClose()
		}
		socket.onclose = () => {
			if(!isCurrent()) return
			logger.warn({ event: BGP_EVENTS.closed })
			onClose()
		}
		socket.onmessage = ({ data }) => {
			if(!isCurrent()) return
			try {
				const str = typeof data === 'string' ? data : data.toString()
				onMessage(str)
			} catch(err) {
				logger.error({ event: BGP_EVENTS.messageInvalid, err })
			}
		}

		function isCurrent(): boolean {
			return !closed && ws === socket
		}

		function onClose(): void {
			if(!isCurrent()) return
			// error followed by close (or any queued callback) retires only once.
			ws = undefined
			retire(socket)
			scheduleReconnect()
		}
	}

	function retire(socket: ReturnType<typeof makeWebSocket>): void {
		socket.onopen = null
		socket.onmessage = null
		socket.onerror = null
		socket.onclose = null
		try {
			socket.close()
		} catch(err) {
			logger.warn({ event: BGP_EVENTS.closeFailed, err })
		}
	}

	function scheduleReconnect(): void {
		if(closed || reconnectTimer !== undefined) return
		logger.info({ event: BGP_EVENTS.reconnecting })
		reconnectTimer = setTimeout(() => {
			reconnectTimer = undefined
			openWs()
		}, reconnectDelay)
		reconnectTimer.unref()
		reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX_MS)
	}

	function onMessage(message: string): void {
		const data = JSON.parse(message)
		const announcements = data?.data?.announcements

		logger.trace({ event: BGP_EVENTS.update })

		if(!Array.isArray(announcements)) {
			return
		}

		const asPath = data?.data?.path

		for(const announcement of announcements) {
			const prefixes = announcement?.prefixes
			const nextHop = announcement?.['next_hop']

			const hasPrefixes = prefixes?.length && (nextHop || asPath)
			if(!hasPrefixes) {
				return
			}

			for(const prefix of prefixes) {
				if(!overlapsTargetIps(prefix)) {
					continue
				}

				// emit event
				eventTarget.dispatchEvent(
					new BGPAnnouncementOverlapEvent({ prefix })
				)
			}
		}
	}

	function overlapsTargetIps(prefix: string): boolean {
		// ignore all prefixes that end with /0
		if(prefix.endsWith('/0')) {
			return false
		}

		const prefixAddress = prefix.includes(':')
			? new Address6(prefix)
			: new Address4(prefix)
		for(const ip of targetIps) {
			try {
				const targetAddress = prefixAddress instanceof Address6
					? new Address6(ip)
					: new Address4(ip)
				if(targetAddress.isInSubnet(prefixAddress)) {
					return true
				}
			} catch {
				// Preserve ip-cidr's false result for invalid target addresses.
			}
		}

		return false
	}
}
