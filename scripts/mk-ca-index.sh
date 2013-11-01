#!/bin/sh
#
# Output sorted list of all certificate subjects

(for file in *.pem; do
	openssl x509 -in $file -noout -subject
done) | sort -u
