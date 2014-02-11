#!/bin/sh

. `dirname $0`/fetch-microsoft-authroot.sh
. `dirname $0`/fetch-microsoft-certs.sh
. `dirname $0`/mk-ca-index.sh > index.txt
rm -f authroot.json
