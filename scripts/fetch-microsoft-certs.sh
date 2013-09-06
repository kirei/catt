#!/bin/sh
#
# Fetch trusted root CAs from Microsoft authroot JSON file

INPUT=authroot.json

if [ ! -r $INPUT ]; then
	echo "Missing input file: $INPUT"
	exit 1
fi

for url in `perl -ne 'print "$1\n" if(/URLToCert.*\"(http:.*)\"/)' < $INPUT`; do

	DER=`basename $url`
	PEM=`basename $url .crt`.pem

	echo "Fetching $DER"
	
	if [ ! -r $PEM ]; then
		curl -s -o $DER $url
		openssl x509 -inform der -in $DER -outform pem -out $PEM
		rm -f $DER
	fi
	
done
