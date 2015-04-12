#!/bin/sh

BUNDLE=ca-bundle.crt
INDEX=index.txt
EV=ev.json
EV_INDEX=ev.txt

rm -f *.pem

sh `dirname $0`/extract-osx-trust.sh > $BUNDLE
perl `dirname $0`/split-bundle.pl < $BUNDLE
rm -f $BUNDLE

sh `dirname $0`/mk-ca-index.sh > $INDEX

perl `dirname $0`/extract-osx-ev.pl > $EV

if [ -f $EV ]; then
	perl `dirname $0`/mk-ev-index.pl < $EV > $EV_INDEX
fi
