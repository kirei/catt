#!/bin/sh
#
# Fetch trusted root CA metadata from Microsoft

URL="http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab"

OUTPUT=authroot.json

CAB=authrootstl.cab
STL=authroot.stl
CTL=authroot.ctl

echo "Downloading '$CAB' ..."  >&2
curl -s -o $CAB $URL

if [ $? -ne 0 -o ! -f $CAB ]; then
	echo "Failed to download '$CAB'"
	exit 1
fi

echo "Extracting '$CAB' ..." >&2
cabextract -s $CAB >&2

if [ $? -ne 0 -o ! -f $STL ]; then
	echo "Failed to extract '$STL'"
	exit 1
fi

echo "Processing '$CAB' ..." >&2
openssl asn1parse -inform der -strparse 63 -in $STL -out $CTL >/dev/null
perl `dirname $0`/parse-microsoft-authroot.pl $CTL > $OUTPUT

rm -f $CAB $STL $CTL
