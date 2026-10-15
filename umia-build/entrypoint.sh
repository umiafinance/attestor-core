#!/bin/sh
set -eu

fail() {
    echo "$1" >&2
    exit 1
}

require_secret() {
    if [ -z "$2" ]; then
        fail "Required attestor secret $1 is missing"
    fi
}

require_secret PRIVATE_KEY "${PRIVATE_KEY-}"
require_secret TOPRF_PUBLIC_KEY "${TOPRF_PUBLIC_KEY-}"
require_secret TOPRF_SHARE_PUBLIC_KEY "${TOPRF_SHARE_PUBLIC_KEY-}"
require_secret TOPRF_SHARE_PRIVATE_KEY "${TOPRF_SHARE_PRIVATE_KEY-}"
require_secret AUTHENTICATION_PUBLIC_KEY "${AUTHENTICATION_PUBLIC_KEY-}"

case "$AUTHENTICATION_PUBLIC_KEY" in
    0x02*|0x03*) expected_length=68 ;;
    0x04*) expected_length=132 ;;
    *) fail 'AUTHENTICATION_PUBLIC_KEY must be a secp256k1 public key' ;;
esac

# A case pattern spans the whole value; grep would accept one matching line.
case "${AUTHENTICATION_PUBLIC_KEY#0x}" in
    *[!0-9a-fA-F]*) fail 'AUTHENTICATION_PUBLIC_KEY must be a secp256k1 public key' ;;
esac
if [ "${#AUTHENTICATION_PUBLIC_KEY}" -ne "$expected_length" ]; then
    fail 'AUTHENTICATION_PUBLIC_KEY must be a secp256k1 public key'
fi

# The server loads .env.$NODE_ENV, and upstream's .env.test enables both test-only knobs below.
case "${NODE_ENV-}" in
    ''|production) ;;
    *) fail 'NODE_ENV must be unset or production' ;;
esac
if [ -n "${ALLOWED_DIRECT_HOSTS+set}" ]; then
    fail 'ALLOWED_DIRECT_HOSTS bypasses the public IP filter and must not be set'
fi
if [ -n "${ACCEPT_CLAIM_PAYMENT_REQUESTS+set}" ]; then
    fail 'ACCEPT_CLAIM_PAYMENT_REQUESTS must not be set'
fi

exec "$@"
