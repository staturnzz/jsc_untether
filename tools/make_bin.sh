#!/bin/bash

OFFSET=`otool -l "$1" | grep fileoff | sed 's/  fileoff //g' | tr -d '\n'`
dd if="$1" of=loader ibs=$OFFSET skip=1
