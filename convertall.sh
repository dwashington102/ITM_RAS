#!/bin/sh
# Shell script to convert hex time in ITM 6 RAS logs to a user friendly format
# User passes the product code to the script, the script will then find all logs
# for that product code in the current directory and convert the timestamps.
#set -x

#export PATH=${PATH}:/cygdrive/c/tasks
rm /tmp/convertallfilelist 1>/dev/null 2>/dev/null

printf "Enter Product Code:  " ; read productcode
printf "Enter Timestamp:  " ; read timestamp
#find . -maxdepth 1 -iname "*${productcode}*_${timestamp}-*.log" -print > /tmp/convertallfilelist 2>/dev/null
find . -maxdepth 1 -iname \*${productcode}*_${timestamp}-\*.log -print > /tmp/convertallfilelist 2>/dev/null

[ -s /tmp/convertallfilelist ]
if [ $? != 0 ]
    then
    printf "No [${productcode}] with timestamp [${timestamp}] Agent Logs found.\n"
	exit 1
else
	for FILENAME in `find . -maxdepth 1 -iname "*_${productcode}*_${timestamp}-*.log" -print`
	do
	convertras.pl $FILENAME
	#convertras1.sh $FILENAME
	printf "\n"
	done
	exit 0
fi

#rm /tmp/convertallfilelist
exit 0
