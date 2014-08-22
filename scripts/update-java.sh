#!/bin/sh

BUNDLE=ca-bundle.crt
INDEX=index.txt
EV=ev.json

perl `dirname $0`/extract-java-trust.pl

