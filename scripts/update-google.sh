#!/bin/sh

SOURCE=https://pki.google.com/roots.pem

BUNDLE=roots.pem
INDEX=index.txt
EV=ev.json
EV_INDEX=ev.txt

rm -f *.pem

curl -o $BUNDLE $SOURCE
perl `dirname $0`/split-bundle.pl < $BUNDLE
rm -f $BUNDLE

sh `dirname $0`/mk-ca-index.sh > $INDEX
