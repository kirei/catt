#!/bin/sh
#
# Fetch trusted root CAs from Microsoft

URL="http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab"

OUTPUT=authroot.json

CAB=authrootstl.cab
STL=authroot.stl
CTL=authroot.ctl

echo "Downloading '$CAB' ..."  >&2
curl -s -o $CAB $URL

echo "Extracting '$CAB' ..." >&2
cabextract -s $CAB >&2

echo "Processing '$CAB' ..." >&2
openssl asn1parse -inform der -strparse 63 -in $STL -out $CTL >/dev/null
perl `dirname $0`/parse-microsoft-authroot.pl $CTL > $OUTPUT

rm -f $CAB $STL $CTL
