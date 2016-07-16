#!/bin/bash
# set -x

# Script to create a PMR directory if one does not exist.
# Directory is created in /mnt/ibm_linux_mount/pmrs  of course you can change this to meet your needs.

PMR=$1

if [ -z "$PMR" ]; then
	printf "PMR:\t "; read PMR
fi

[ -d /mnt/ibm_linux_mount/pmrs/$PMR ]
unknown=`echo $?`

# If the directory does exist, a subdirectory with today's date is added.
if [ "$unknown" = 0 ]
	then
#	dir=`date "+%Y%m%d"`
	datedir=$(date +"%Y%m%d")
	printf "Creating directory: /mnt/ibm_linux_mount/pmrs/$PMR/$datedir\n"
	mkdir /mnt/ibm_linux_mount/pmrs/$PMR/$datedir
	printf "\n"
		
else
# If the directory does NOT exist,the directory and subdirectory with today's date is created.
#	dir=`date "+%Y%m%d"`
	datedir=$(date +"%Y%m%d")
	printf "Creating directory: /mnt/ibm_linux_mount/pmrs/$PMR/$datedir\n"
	mkdir -p /mnt/ibm_linux_mount/pmrs/$PMR/$datedir
	
fi
	printf "\n"
exit 0
