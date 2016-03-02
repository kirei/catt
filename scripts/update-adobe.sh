#!/bin/sh

URL="http://trustlist.adobe.com/tl10.acrobatsecuritysettings"
TL=tl10.acrobatsecuritysettings
INDEX=index.txt

echo "Downloading '$TL' ..." >&2
curl -s -o $TL $URL

if [ $? -ne 0 -o ! -f $TL ]; then
	echo "Failed to download '$TL'"
	exit 1
fi

rm -f *.pem

python2 `dirname $0`/extract-adobe-aatl.py $TL
rm -f $TL

. `dirname $0`/mk-ca-index.sh > $INDEX
