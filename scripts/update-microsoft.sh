#!/bin/sh

INDEX=index.txt
EV=ev.json
EV_INDEX=ev.txt

rm -f *.pem

. `dirname $0`/fetch-microsoft-authroot.sh
. `dirname $0`/fetch-microsoft-certs.sh
rm -f authroot.json

. `dirname $0`/mk-ca-index.sh > $INDEX

if [ -f $EV ]; then
	perl `dirname $0`/mk-ev-index.pl < $EV > $EV_INDEX
fi
