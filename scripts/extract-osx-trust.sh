#!/bin/sh
#
# Extract all trusted CAs for OSX system chain

KEYCHAIN=${1:-"/System/Library/Keychains/SystemRootCertificates.keychain"}

echo "Exporting trusted CAs from ${KEYCHAIN}" >&2
security export -k $KEYCHAIN -t certs
