#!/bin/sh
#
# Extract all trusted CAs for OSX system chain

KEYCHAIN="/System/Library/Keychains/SystemRootCertificates.keychain"

security export -k $KEYCHAIN -t certs
