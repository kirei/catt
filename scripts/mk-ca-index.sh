#!/bin/sh

for file in *.pem; do
	openssl x509 -in $file -noout -subject
done
