#!/bin/sh

BUNDLE=ca-bundle.crt
INDEX=index.txt
EV=ev.json
EV_INDEX=ev.txt

rm -f *.pem

perl `dirname $0`/mk-ca-bundle.pl && rm -f certdata.txt

if [ -f $BUNDLE ]; then
	perl `dirname $0`/split-bundle.pl < $BUNDLE
	sh `dirname $0`/mk-ca-index.sh > $INDEX
	rm -f $BUNDLE
fi

python `dirname $0`/extract-mozilla-ev.py -f json | json_pp > $EV

if [ -f $EV ]; then
	perl `dirname $0`/mk-ev-index.pl < $EV > $EV_INDEX
fi
