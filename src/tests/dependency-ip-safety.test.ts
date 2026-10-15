import assert from 'node:assert/strict'
import { it, mock } from 'node:test'
import { Wallet } from 'ethers'

process.env.PRIVATE_KEY = Wallet.createRandom().privateKey
process.env.CLAIM_EPOCH = '2'

let resolved: string[] = []
mock.module('#src/server/utils/dns.ts', {
	namedExports: {
		async resolveHostnames() { return resolved }
	}
})

const { getPublicAddresses } = await import('#src/server/utils/generics.ts')

it('retains IPv4 filtering and rejects IPv6 or ambiguous DNS answers', async() => {
	for(const [ip, allowed] of [
		['8.8.8.8', true],
		['1.1.1.1', true],
		['172.32.0.1', true],
		['100.128.0.1', true],
		['10.0.0.1', false],
		['10.255.255.255', false],
		['172.16.0.1', false],
		['172.31.255.255', false],
		['192.168.0.1', false],
		['192.168.255.255', false],
		['127.0.0.1', false],
		['127.255.255.255', false],
		['169.254.169.254', false],
		['100.64.0.1', false],
		['100.127.255.255', false],
		['192.0.2.1', false],
		['198.51.100.1', false],
		['203.0.113.1', false],
		['198.18.0.1', false],
		['198.19.255.255', false],
		['240.0.0.1', false],
		['255.255.255.255', false],
		['224.0.0.1', false],
		['239.255.255.255', false],
		['0.0.0.0', false],
		['012.0.0.1', false],
		['2606:4700:4700::1111', false],
		['fc00::1', false],
		['fe80:1::1', false],
		['ff02::1', false],
		['::', false],
		['::1', false],
		['::ffff:10.0.0.1', false],
		['::10.0.0.1', false],
		['::ffff:8.8.8.8', false],
		['64:ff9b::a00:1', false],
		['64:ff9b:1:7f00:0:100::', false],
		['64:ff9b:1::a00:1', false]
	] as const) {
		resolved = [ip]
		if(allowed) assert.deepEqual(await getPublicAddresses('reviewed.example'), [ip], ip)
		else await assert.rejects(getPublicAddresses('reviewed.example'), undefined, ip)
	}

	resolved = ['10.0.0.1', '8.8.8.8']
	assert.deepEqual(await getPublicAddresses('reviewed.example'), ['8.8.8.8'])
	resolved = ['8.8.8.8', '2606:4700:4700::1111']
	await assert.rejects(getPublicAddresses('reviewed.example'))
})
