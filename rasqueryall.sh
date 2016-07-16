#!/bin/sh

for FILENAME in `cat /tmp/files.txt`
	do rasquery.pl $FILENAME
done
