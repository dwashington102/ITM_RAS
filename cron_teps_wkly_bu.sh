#!/bin/sh
# Create Date: 2014-10-05
# Name: cron_teps_wkly_bu.sh
# Description: 
# Created a weekly backup of the TEPS database.  The usual saveexport.sql file will include an extension that includeds the date when the file was created.
# To save space, the script will remove saveexport.sql files older than 30 days. 


################## Defined Variables  ##############################
TIMESTAMP=`date "+%Y%m%d"`
export CANDLEHOME=/opt/IBM/ITM
export PATH=/opt/IBM/ITM/bin:${PATH}

################## Defined Variables  ##############################

#echo "TIMESTAMP=$TIMESTAMP"
#echo "CANDLEHOME=$CANDLEHOME"
#echo "PATH=$PATH"


[ -e $CANDLEHOME/lx8266/cq/sqllib/saveexport.sql_"$TIMESTAMP" ]
unknown=`echo $?`

#echo "DEBUG >>>> $unknown"

if [ "$unknown" != 0 ]
	then
		itmcmd execute cq "runscript.sh migrate-export.sh" 2>/dev/null
		mv $CANDLEHOME/lx8266/cq/sqllib/saveexport.sql $CANDLEHOME/lx8266/cq/sqllib/saveexport.sql_"$TIMESTAMP"
	else
		mv $CANDLEHOME/lx8266/cq/sqllib/saveexport.sql $CANDLEHOME/lx8266/cq/sqllib/saveexport.sql_BAK 2>/dev/null
fi

find $CANDLEHOME/lx8266/cq/sqllib -name 'saveexport.sq*' -type f -mtime +30 -exec rm -f {} \;

exit 0
