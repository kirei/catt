#!/bin/sh
#
# Fetch trusted root CAs from Microsoft authroot JSON file

INPUT=authroot.json

if [ ! -r $INPUT ]; then
	echo "Missing input file: $INPUT"
	exit 1
fi

for url in `perl -ne 'print "$1\n" if(/URLToCert.*\"(http:.*)\"/)' < $INPUT`; do

	BASE=`basename $url .crt`

	DER=${BASE}.crt
	PEM=${BASE}.pem

	echo "Fetching $DER"
	
	if [ ! -r $PEM ]; then
		echo "Found new certificate ${BASE}"
		curl -s -o $DER $url
		openssl x509 -inform der -in $DER -outform pem -out $PEM
		rm -f $DER
	else
		echo "Skipped existing certificate ${BASE}"
	fi
	
done
