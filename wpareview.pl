#!/usr/bin/perl -w
# wpareview.pl
# Date: 2010/08/21
#------------------------------------------------------------------------------
# Licensed Materials - Property of IBM (C) Copyright IBM Corp. 2010, 2010
# All Rights Reserved US Government Users Restricted Rights - Use, duplication
# or disclosure restricted by GSA ADP Schedule Contract with IBM Corp
#------------------------------------------------------------------------------
# Script is AS-IS and not supported by IBM Support.
#------------------------------------------------------------------------------
# Script will parse RAS logs for the Warehouse Proxy Agent, gather useful information,
# and identify common errors found in the log.
# Author: David Washington
# washingd@us.ibm.com
#################################################################################
#
# Revision History:
# Revision 2.0.10 2016/03/04
#	Added search to detect dynamic trace setting change "KBBRA_ChangeLogging"
# Revision 2.0.9 2016/01/27
# 	Added err_ctx_warehouseproxynotregistered
# Revision 2.0.8 2015/07/03
# 	Added DB2CODEPAGE setting to the getdbinfo_win()
# Revision 2.0.7 2013/12/13
# 		Added search for add_listener
# 		Added getdbinfo()
# 		Added getdbinfo_win()
# Revision 2.0.6 2013/08/17
#	Changed ARcmssplit to split at "Successfully connected to CMS" rather than "CT_CMSLIST"
# Revision 2.0.5 2013/07/30
#	Added search for CANDLEHOME
# Revision 2.0.4 2013/04/29
#	Added search for "Process ID" 
# Revision 2.0.3 2012/10/30
# 	Added err_ctx_init()
#
# Revision 2.0.2 2012/08/19
#	Added search for Nofiles Descriptor Setting
#
# Revision 2.0.1 2012/08/08
#	Added err_ctx_getcurrentstatus()
#
# Revision 2.0 2011/02/14
#	Added err_createrouterequest()
#	
# Revision 1.9 2010/12/09
# 	Replaced references to @label[1] in else{} when printing, with /m for theses arrays:
#	>  @ARPortassign
# 	Change err_219 search string 
#	OLD: my @ARErr219list=grep(/Error\s219\shappened\s(.*?)\)$/i,@ARLogarray);
# 	NEW: my @ARErr219list=grep(/Error\s219\shappened\s(.*?)\)/i,@ARLogarray);
#
# Revision 1.8 2010/10/24
# 	Added err_datasource() and err_rpctonode
#
# Revision 1.7 2010/10/10
#	changed get_EOF() replaced 
#	> my @AREof=grep(/^\(/,$sPoplogarray);
#
# Revision 1.6 2010/09/24:
#	changed $sSysType to use match rather than splitting array
#	changed get_EOF() to get last element of @ARLogarray rather than pop @ARLogarray
#
# Revision 1.5 2010/09/15:
#	added check_filename() - confirms file passed is valid
#
# Revision 1.4 2010/09/14:
#	get_cms_connectdate() - Added to print date/time agent connects to TEMS
#	added 0 byte size checking (-z $mostrctlog)
#	added access permission checking (!-r $mostrctlog)
#	added err_ctx_odbcerror
#
# Revision 1.3 2010/09/07:
#	err_ora() -Added to detect various Oracle errors
#	@ARDberrlist - Added for logic reason
#
# Revision 1.2 2010/08/28:
#	sql1224n() - Removed. 
#	@ARsql1032n - Changed search string to include |SQL10224N
#	get_EOF()  - Added to detect EOF
#
# Revision 1.1 2010/08/23:
#	@ARReject - changed output from hextime to wall clock time
#	err_219() - minor format changes adding \n 
# 	err_connectionlost() - Added header "Connection Lost Errors"
#
# Revision 1.0 2010/02/01					
#################################################################################
use strict;
use warnings;
use Cwd;
use Term::ANSIColor;

##################################################################################
##########################       Set Variables            ########################
##################################################################################

my $currentdir = cwd;
my $iforloop =0;
my $iforloopnic =1;

# Searches used to extract debug level and system  information from all ITM logs.
my $searchitmdebug=("KBB_RAS1:");
my $searchdynamicdebug=("KBBRA_ChangeLogging");
my $searchitmsystemname=("System Name: ");
my $searchitmsystemtype=("System Type: ");
my $searchitmstartdate=("Start Date: ");
my $searchitmstarttime=("Start Time: ");
my $searchitmcomponent=("Component: ");
my $searchitmdriver=("Driver: ");
my $searchusername=(" User Name: ");
my $searchnofile=(" Nofile Limit: ");
my $searchpid=(" Process ID: ");
my $searchcandlehome=(" CANDLEHOME=\"");

# Searches used to extract network information.
my $searchitmipaddr=("source=");
my $searchkdc=("=KDC_FAMILIES=");
my $searchagentport=("KDEBP_AssignPort");
my $searchhttpkdhsqlqm=("kdhslqm.*add_listener.*listening");
my $searchctirahostname=("CTIRA_HOSTNAME");
my $searchkdebinterface=(" KDEB_INTERFACELIST");
#my $searchitmcms=(" CT_CMSLIST");
my $searchitmcms=("\"ConnectToProxy\"");
my $searchregister=("Registering \"Candle_Warehouse_Proxy\"");
my $searchtemslist=("KHD_WAREHOUSE_TEMS_LIST=\"");
my $searchwpaready=("Export Server Ready");

#Searched specific to WPA logs
my $searchjavahome=("JAVA_HOME=\"");
my $searchjdbcdriver=("KHD_JDBCDRIVER=\"");
my $searchwarehousejars=("KHD_WAREHOUSE_JARS=\".*jar\"");
my $searchwpajavaargs=("KHD_JAVA_ARGS=\"");
my $searchnlslang=("NLS_LANG=\"");
my $searchconnection=("Connection with Datasource");
my $searchkhdbatch=("KHD_BATCH_USE is set to");
my $searchwindb=("getDatabaseInfo\"");
my $searchdbuser=("KHD_WAREHOUSE_USER");

# undefined variables
my $sHost=undef;
my $sStarttime=undef;
my $sIpaddrsplt=undef;
my $scomponentmatch=undef;
my $sHextime=undef;
my $sSysT=undef;
my $sSysType=undef;
my $sStartTime=undef;
my $sPortassign=undef;
my $key=undef;
my $value=undef;
my $sDatasourcefailed=undef;
my $sRpcerrortonode=undef;

undef my @ARRpcerrortonode;
undef my @ARDatasourcefailed;
undef my @ARctirahost;
undef my @ARWpaconfig;
undef my @AREnv;
my $sKdhslqm=undef;

# Common errors found in RAS logs 
my $searchcmsrunning=("Unable to find running CMS");

#################################################################################
# Get LocalHost OS                                                              #
#################################################################################
my $sRawOS=$^O;
#print "Debug Value Raw: $sRawOS\n";
my $sLocalhostos=substr($sRawOS,0,5);

if ($sLocalhostos eq "MSWin") {
        $sLocalhostos=("Windows");
#        print "DEBUG: Operating System: $sLocalhostos\n";
} else {
	$sLocalhostos=$sRawOS;
#        print "DEBUG: Operating System: $sLocalhostos\n";
}
#################################################################################

##################################################################################
#########################       Main Program      ################################
##################################################################################
my $mostrctlog=$ARGV[0] or die "Usage: wpareview.pl [RAS LOG]\n\n";
check_filename();
open (LOG,"<$mostrctlog");
my @ARLogarray =  <LOG>;
close(LOG);

##################################################################################
# Allows script to run against RAS logs other than the RAS1 log 
my $RAS = rindex($mostrctlog, '1.log');
##################################################################################

print "\n#######################################################\n";
print "\t\t$mostrctlog\n";
print "#######################################################\n";

if ($RAS >=0) {

# Remove any output files from current directory.
unlink("$mostrctlog.reviewras.dbinserts");
unlink("$mostrctlog.reviewras.db2err");

# Check if host server is running MS-Windows
my @WPAserverOS=grep(/\skhdxprto\s+System\sType:\sWin/i,@ARLogarray);

# Gather the KBB_RAS1 setting
my @itmmatchdebug = grep(/$searchitmdebug/, @ARLogarray) or print "KBB_RAS1 setting not found.\n";
if ($#itmmatchdebug < 0 ) {
	print "Confirm KBB_RAS1 setting is enabled.\n";
} else {
	my $shiftmatchdebug = shift(@itmmatchdebug);
	my @debuglevel=split(/KBB_RAS1[=|:]/,$shiftmatchdebug);
	chomp(@debuglevel);
	my $rasdebug=pop(@debuglevel);
	print "\n#######################################################\n";
	print "Debug Setting: $rasdebug\n";
	my @ARKdcdebug=grep(/KD[C|E]_DEBUG/,@ARLogarray); 
	if ($#ARKdcdebug >= 0) {
 		foreach my $sKdcdebug(@ARKdcdebug) {
		$sKdcdebug =~ s/\(\w+(.*?)\)//g;
		print "$sKdcdebug";
		}
	} 
	
}
my @itmdynamicdebug = grep(/$searchdynamicdebug/, @ARLogarray) or print "Dynamic debug trace not set\n";
	if ($#itmdynamicdebug < 0 ) {
		print "#######################################################\n";
	} else {
	print "Trace Level Changed:\n";
	foreach my $sItmdynamicdebug(@itmdynamicdebug){
		my @debuglevel=split(/KBBRA_ChangeLogging\"\)\ /,$sItmdynamicdebug);
		chomp(@debuglevel);
		my $dynamicdebug=pop(@debuglevel);
		print "$dynamicdebug\n";
	}
		print "#######################################################\n";
	}

print "\n#######################################################\n";
print "Hostname, Operating System, and Start Date/Time:\n";
my @itmmatchsystem = grep(/$searchitmsystemname/, @ARLogarray) or print "HOSTNAME:\t";
if ($#itmmatchsystem < 0 ) {
	print " NOT FOUND\n";
} else {
	my $shiftmatchsystem = shift(@itmmatchsystem);
	my @systemname=split(/KBB_RAS1:/,$shiftmatchsystem);
	my $sString="@systemname";
	($sHost) = $sString =~ m/System Name:\s+(.*?)\s+/;
	print "HostName: $sHost\n";
}

my @itmmatchtype = grep(/$searchitmsystemtype/, @ARLogarray) or print "System Type:\t";
if ($#itmmatchtype < 0 ) {
	print " NOT FOUND\n";
} else {
	my $shiftmatchtype = shift(@itmmatchtype);
	my ($sSysType) = $shiftmatchtype =~ m/System\sType:\s(.*?)\s+?/;
	print "System Type: $sSysType\n";
}

my @itmmatchdate = grep(/$searchitmstartdate/, @ARLogarray) or print "Start Date:\t";
if ($#itmmatchdate < 0) {
	print " NOT FOUND\n";
} else {
	my $shiftmatchdate = shift(@itmmatchdate);
	my @startdate=split(/Start Date:/,$shiftmatchdate);
	chomp(@startdate);
	my $sStartdate=substr($startdate[1],0,12);
	print "Start Date: $sStartdate\n";
}

my @itmmatchtime = grep(/\d+\s+$searchitmstarttime/, @ARLogarray) or print "Start Time:\t";
if ($#itmmatchtime < 0) {
	print " NOT FOUND\n";
} else {
	my $shiftmatchtime = shift(@itmmatchtime);
	my @ARstarttime=split(/Start Time:/,$shiftmatchtime);
	($sStartTime)=substr($ARstarttime[1],0,10);
	print "Start Time: $sStartTime\n";
}

my @itmmatchusername=grep(/$searchusername/,@ARLogarray) or my $sUsernamenull=("NOT FOUND");
if ($#itmmatchusername < 0) {
	$sUsernamenull=("NOT FOUND");
} else {
	my $shiftmatchusername=shift(@itmmatchusername);
	my @splitusername=split(/User Name:/,$shiftmatchusername);
	chomp(@splitusername);
	my $sUsername="$splitusername[1]";
	print "Process running as USERID: $sUsername\n";
}

my @itmmatchnofile=grep(/$searchnofile/,@ARLogarray) or my $sNofile=("NOT FOUND");
if ($#itmmatchnofile < 0) {
	$sNofile=("NOT FOUND");
} else {
	my $shiftnofile=shift(@itmmatchnofile);
	my @ARsplitnofile=split(/Nofile Limit:/,$shiftnofile);
	chomp(@ARsplitnofile);
	my ($sNofile)=substr($ARsplitnofile[1],0,10);
	print "Nofile Descriptor Limit: $sNofile\n";
}

my @itmmatchpid=grep(/$searchpid/,@ARLogarray) or my $sPidnull=("NOT FOUND");
if ($#itmmatchpid < 0) {
	$sPidnull=("NOT FOUND");
} else {
	my $shiftmatchpid=shift(@itmmatchpid);
	my ($sPid) = $shiftmatchpid =~ m/Process\sID:\s(.*?)\s+?/i;
	print "Process ID: $sPid\n";
}

my @itmmatchcandlehome=grep(/$searchcandlehome/,@ARLogarray) or my $sCandlehome=("NOT FOUND");
if ($#itmmatchcandlehome < 0) {
	$sCandlehome=("NOT FOUND");
} else {
	my $shiftmatchcandlehome=shift(@itmmatchcandlehome);
	my @splitmatchcandlehome=split(/CANDLEHOME=/,$shiftmatchcandlehome);
	chomp(@splitmatchcandlehome);
	my $sCandlehome="$splitmatchcandlehome[1]";
	print "CANDLEHOME: $sCandlehome\n";
}


print "#######################################################\n";

print "\n#######################################################\n";
print "Network Information:\n";
my @ARipaddrmatch = grep (/\.\d+:\s$searchitmipaddr/,@ARLogarray) or print "\nIP address:\t";
if ($#ARipaddrmatch < 0) {
	print " NOT FOUND\n";		
} else {
foreach	my $sIpaddrstr (@ARipaddrmatch) {
	($sIpaddrsplt) = $sIpaddrstr =~ m/.\w\s+(.*?):\s+source=/;
	print "Network Interface Card[$iforloopnic]: $sIpaddrsplt\n";
	$iforloopnic++;
	}
}

my @ARkdcfamilies = grep (/$searchkdc/,@ARLogarray) or print "\nKDC_Families and Port Assignment:\t";
if ($#ARkdcfamilies < 0) {
	print " NOT FOUND\n";
} else {
	$_=shift(@ARkdcfamilies);
	my ($sKdcfamilies) = $_ =~ m/=KDC_FAMILIES="(.*?)"/;
	print "\nKDC_FAMILIES setting:\n$sKdcfamilies\n";
}

my @ARPortassign=grep(/$searchagentport\"\)\s\w(.*?)\sbound\sto\sport\s/, @ARLogarray) or print "\nPort Assignment ";
if ($#ARPortassign < 0) {
	print " NOT FOUND\n";
}
else {
	print "\nPort Agent is connected to:\n";
	foreach $sPortassign (@ARPortassign) {
		($sPortassign) = $sPortassign =~ m/_AssignPort"\)\s(.*?)$/;
		print "$sPortassign\n";
	}
}

my @ARkdhslqm=grep(/$searchhttpkdhsqlqm/,@ARLogarray) or print "Kdhslqm:\t";
if ($#ARkdhslqm < 0) {
	print "NOT FOUND\n";
}
else {
	print "\nAgent Registered with Monitoring Service Index Using Ports (add_listener):\n";
	foreach $sKdhslqm (@ARkdhslqm) {
		($sKdhslqm) = $sKdhslqm =~ m/add_listener"\)\s(.*?)$/;
		print "$sKdhslqm\n";
	}
}

my @ARctirahostname=grep(/$searchctirahostname/,@ARLogarray);
if ($#ARctirahostname < 0) {
	print "\nCTIRA_HOSTNAME is not set.\n";
} else {
	my $sShiftctirahostname=shift(@ARctirahostname);	
	@ARctirahost=split(/CTIRA_HOSTNAME=/,$sShiftctirahostname);
	chomp(@ARctirahost);
	print "\nCTIRA_HOSTNAME set to $ARctirahost[1]\n";
}

my @ARKdebinterfacelist=grep(/$searchkdebinterface/,@ARLogarray);
#print "DEBUG>>>>> $#ARKdebinterfacelist\n";
if ($#ARKdebinterfacelist <= 0) {
	my $skdebinterface=("NOT SET");
} else {
	my $sShiftkdebinterfacelist=shift(@ARKdebinterfacelist);
	my @ARKdebintersplit=split(/KDEB_INTERFACELIST=/,$sShiftkdebinterfacelist);
	chomp(@ARKdebintersplit);
	print "\nKDEB_INTERFACELIST=$ARKdebintersplit[1]\n";
}

my @itmcmsfound=grep(/$searchitmcms/,@ARLogarray) or print "\nAgent's configuration to TEMS";
if ($#itmcmsfound < 0) {
	print " NOT FOUND.\n";
} else {
	my $sShiftcmsfound=shift(@itmcmsfound);
#	Changed on 8/17/2013:  my @ARcmssplit=split(/CT_CMSLIST=/,$sShiftcmsfound);
	my @ARcmssplit=split(/Successfully connected to CMS\s/,$sShiftcmsfound);
	chomp(@ARcmssplit);
	print "\nAgent configured to connect to TEMS: $ARcmssplit[1]\n";
	get_cms_connectdate();
}


my @registerfound=grep(/$searchregister/i,@ARLogarray) or print "\nUnable to locate Candle_Warehouse_Proxy ";
if ($#registerfound < 0) {
	print "registration within WPA log.\n";
} else {
	my $sShiftregister=shift(@registerfound);
	my @ARregistersplit=split(/Registering/,$sShiftregister);
	chomp(@ARregistersplit);
	print "\nWPA is registered at TEMS to use:  $ARregistersplit[1]\n";
}

my @itmtemslistfound=grep(/$searchtemslist/i,@ARLogarray) or print "\nKHD_WAREHOUSE_TEMS_LIST ";
if ($#itmtemslistfound < 0) {
	print "is not set.\n";
} else {
	my $sShifttemslist=shift(@itmtemslistfound);
	my @ARtemslistsplit=split(/KHD_WAREHOUSE_TEMS_LIST=/,$sShifttemslist);
	chomp(@ARtemslistsplit);
	print "\nWPA is set to handle exports from TEMS: KHD_WAREHOUSE_TEMS_LIST=$ARtemslistsplit[1]\n";
}

my @wpareadyfound=grep(/$searchwpaready/i,@ARLogarray) or print "\n>>>   Export Server Ready message";
if ($#wpareadyfound < 0) {
	print " NOT FOUND in WPA log.  Confirm WPA is ready for exports.   <<<\n";
} else { 
	print "\nWPA status: READY for Exports\n";
}
print "\n#######################################################\n";

print "\n#######################################################\n";
print "WPA Database Connection Information:\n\n";

##########################################################
# Gathering database information for Windows host
##########################################################
if ($#WPAserverOS >= 0) {
	dbconnection_test();
	dbtype();

	my @DBVERSIONwin=grep(/$searchwindb\)\s(.*?)DBMS_VERSION/i,@ARLogarray) or print "\nDatabase Version Information ";
	if ($#DBVERSIONwin < 0) {
        print " NOT FOUND.\n";
	} else {
        my $sShiftdbversionwin=shift(@DBVERSIONwin);
        my @splitdbversionwin=split(/=\s/,$sShiftdbversionwin);
        chomp(@splitdbversionwin);
        print "Database Version:\n\t$splitdbversionwin[1]\n";
	}

	my @ARDatasource=grep(/$searchwindb\)\sSQL_DATA_SOURCE_NAME\s+=/i,@ARLogarray) or print "\nSQL_DATA_SOURCE_NAME";
	if ($#ARDatasource < 0) {
		print " NOT FOUND.\n";
	} else {
		my $sShiftdatasource=shift(@ARDatasource);
		my @splitdatasource=split(/=/,$sShiftdatasource);
		chomp(@splitdatasource);
		print "DATA SOURCE:\n\t$splitdatasource[1]\n";
	}

	my @ARKhduser=grep(/$searchdbuser/i,@ARLogarray) or print "KHD_WAREHOUSE_USER";
	if ($#ARKhduser < 0) {
		print "DEBUG NOT FOUND.\n";
	} else {
		my $sShiftkhduser=shift(@ARKhduser);
		my @splitkhduser=split(/=/,$sShiftkhduser);
		chomp(@splitkhduser);
		print "KHD_WAREHOUSE_USER:\n\t$splitkhduser[1]\n";
	}
	get_khdbatchuse();
	getdbinfo_win();
	
############################################################	
# Gathering database information for Linux/UNIX host	
##########################################################
} else {
	dbconnection_test();
	dbtype();

	my @jdbcdriver=grep(/$searchjdbcdriver/,@ARLogarray) or print "JDBC Driver information";
	if ($#jdbcdriver < 0) {
		print " NOT FOUND.\n";
	} else {
		my $sShiftjdbcdriver=shift(@jdbcdriver);
		my @splitjdbc=split(/KHD_JDBCDRIVER=/,$sShiftjdbcdriver);
		chomp(@splitjdbc);
		print "\nJDBC Driver Information:\n\t$splitjdbc[1]\n";
	}

	my @ARjavahome=grep(/$searchjavahome/,@ARLogarray) or print "JAVA_HOME information";
	if ($#ARjavahome < 0) {
		print " NOT FOUND.\n";
	} else {
		my $sShiftjavahome=shift(@ARjavahome);
		my @splitjavahome=split(/JAVA_HOME=/,$sShiftjavahome);
		chomp(@splitjavahome);
		print "JAVA HOME:\n\t$splitjavahome[1]\n";
	}

	my @warehousejars=grep(/$searchwarehousejars/,@ARLogarray) or print "\nWarehouse JAR information";
	if ($#warehousejars < 0) {
		print " NOT FOUND.\n\n";
	} else {
		my $sShiftwarehousejars=shift(@warehousejars);
		my @splitjars=split(/KHD_WAREHOUSE_JARS=/,$sShiftwarehousejars);
		chomp(@splitjars);
		print "WAREHOUSE JARS Information:\n\t$splitjars[1]\n";
	}

	my @nlslang=grep(/$searchnlslang/,@ARLogarray) or print "\nNLS_LANG value";
	if ($#nlslang < 0) {
		print " NOT FOUND.\n";
	} else {
		my $sShiftlang=shift(@nlslang);
		my @splitlang=split(/NLS_LANG=/,$sShiftlang);
		chomp(@splitlang);
		print "NLS_LANG Information:\n\t$splitlang[1]\n"; 
	}

	my @DBUSERID=grep(/SQLTables\susing\sowner/i,@ARLogarray) or print "Database Userid Information";
	if ($#DBUSERID < 0) {
        	print " NOT FOUND.\n";
	} else {
       		my $sShiftdbuserid=shift(@DBUSERID);
       		my @splituserid=split(/owner\s/,$sShiftdbuserid);
       		chomp(@splituserid);
       		print "Database UserID:\n\t$splituserid[1]\n";
	}
	get_khdbatchuse();
	getdbinfo();
}

print "\n#######################################################\n";
print "\n#######################################################\n";
print "Internal Components and Driver Levels:\n";
get_compdriverlvl();
print "\nComponent khd is Warehouse Proxy Agent\n";
print "\nTo match driver levels to ITM 6 versions, see URL:\nhttp://www-01.ibm.com/support/docview.wss?uid=swg27008514\n";
print "#######################################################\n";
print "\n#######################################################\n";
print "Errors Messages Found in RAS LOG:\n";
itm_errors();
err_datasource();
reject();
err_219();
err_rpctonode();
err_connectionlost();
err_ctx_odbcerror();
err_ctx_getcurrentcms();
err_createrouterequest();
err_ctx_init();
err_ctx_warehouseproxynotregistered();

my @ARDberrlist=grep(/ORA-/,@ARLogarray);
	if ($#ARDberrlist >= 0) {
	# Include functions to detect Oracle errors
	#err_oraclepreparedstatement();
	err_ora();
	ora_01034();
	} else {
	# Include functions to detect DB2 errors
	err_db2();
	sql1032n();
	utf8();
	}
print "\n#######################################################\n";

my @ARInsertcheck=grep(/\"endProcessSample\"\)\sInserted\s\d+\srows\sof\sdata/i,@ARLogarray);
if ($#ARInsertcheck >=0) {
print "\n#######################################################\n";
print "Inserting historical data into DataWarehouse:\n";
tdw_inserts();
print "\n#######################################################\n";
} 
print "\n#######################################################\n";

###############################################################
# Used for RAS logs other than RAS1 log.
###############################################################
} else {

my @dbconnection=grep(/initializeDatabase\"\)\s$searchconnection/,@ARLogarray);
if ($#dbconnection >= 0) {
	dbconnection_test();
}

my @ARDbmstype=grep(/SQL_DBMS_NAME|KHD_DBMS/i,@ARLogarray);
if ($#ARDbmstype >= 0) {
	dbtype();
} 

my @ARkhdbatch=grep(/$searchkhdbatch/,@ARLogarray);
if ($#ARkhdbatch >= 0) {
	get_khdbatchuse();
} 
print "\n#######################################################\n";
print "Errors Messages Found in RAS LOG:\n";
itm_errors();
reject();
err_219();
err_connectionlost();
my @ARDberrlist=grep(/ORA-/,@ARLogarray);
	if ($#ARDberrlist >= 0) {
	# Include functions to detect Oracle errors
	err_ora();
	ora_01034();
	} else {
	# Include functions to detect DB2 errors
	err_db2();
	sql1032n();
	utf8();
	}
print "\n#######################################################\n";
my @ARInsertcheck=grep(/\"endProcessSample\"\)\sInserted\s\d+\srows\sof\sdata/i,@ARLogarray);
if ($#ARInsertcheck >=0) {
print "\n#######################################################\n";
print "Inserting historical data into DataWarehouse:\n";
tdw_inserts();
print "\n#######################################################\n";
} else {
	my $sExportcheck=("none");
}
}
get_EOF();

print "\n#######################################################\n";
#Used to convert timestamps within RAS logs
print "Do you want to convert HEX timestamps in $mostrctlog (type \"yes\" or \"no\"):  \t";
my $sCONVERT=<STDIN>;
chomp($sCONVERT);
if (($sCONVERT eq "yes")||($sCONVERT eq "YES")) {
	system ("convertras.pl $mostrctlog");
}
print "\n#######################################################\n";
print "Review of $mostrctlog completed.\n\n";
exit(0);

##################################################################################
#####################        Subroutines       ###################################
##################################################################################
sub tdw_inserts {
my $searchitmdebug=("KBB_RAS1:");
open(LOG,"<$mostrctlog");
my @ARLogarray = <LOG>;
close(LOG);

my @ARInserts=grep(/\"endProcessSample\"\)\sInserted\s\d+\srows\sof\sdata/i,@ARLogarray);
if ($#ARInserts < 0) {
	my @itmmatchdebug = grep(/$searchitmdebug/, @ARLogarray) or print "\nKBB_RAS1 setting not found in $mostrctlog.\n";
	if ($#itmmatchdebug < 0 ) {
	print "Confirm KBB_RAS1 setting has UNIT khdx enabled.\n";
	exit(0);
	} else {
	my $shiftmatchdebug = shift(@itmmatchdebug);
	my @debuglevel=split(/KBB_RAS1:/,$shiftmatchdebug);
	chomp(@debuglevel);
	my @ARRasdebug=grep(/khdx/i,@debuglevel);
		if ($#ARRasdebug < 0) {
		print "\nLog $mostrctlog KBB_RAS1 trace level does not include UNIT:KHDX.\nData Exports not found in log.\n";
		} else {
		print "KBB_RAS1 is tracing KHDX UNIT, but no data exports were found in the log.\n";
		}
	}
} elsif ($#ARInserts > 10) {
	my $poptdwinserts=pop(@ARInserts);
	$poptdwinserts=($poptdwinserts =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	open(DBINSERTS,">reviewras.dbinserts");
	foreach my $sDbinserts(@ARInserts) {
		$sDbinserts=($sDbinserts =~ /^(.)([\dA-F]+)(\..*)/);
		printf DBINSERTS "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}
	close(DBINSERTS);
	open(INSERTFILE,"<reviewras.dbinserts");
	open(DBINSERTFILE,">$mostrctlog.reviewras.dbinserts");
	while (<INSERTFILE>) {
		s/^\s$//;
		s/\x0D//g;
		print DBINSERTFILE "$_\n";
	}
	unlink("reviewras.dbinserts");
	close("INSERTFILE");
	close("DBINSERTS");
	print "\nTotal number of data warehouse inserts found in WPA Log: $#ARInserts\n";
	#print "\nMore than 10 data warehouse inserts found in WPA Log.\n";
	print "Data Inserts stored in $mostrctlog.reviewras.dbinserts\n";
} else {
	foreach my $ARExportline(@ARInserts) {
		if ($ARExportline =~ /status\s0$/) {
			$ARExportline=($ARExportline =~ /^(.)([\dA-F]+)(\..*)/); 
			printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
		} else {
			$ARExportline=($ARExportline =~ /^(.)([\dA-F]+)(\..*)/); 
			print color 'bold';
			printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
			print color 'reset';
		}
	}
}
}

sub dbconnection_test {
my @dbconnection=grep(/$searchconnection/,@ARLogarray) or print "\nConnection to Datasource";
if ($#dbconnection < 0) {
	print " NOT FOUND.\n";
} else {
	my $sShiftconnection=shift(@dbconnection);
	my @splitconnection=split(/initializeDatabase\"\)/,$sShiftconnection);
	chomp(@splitconnection);
	print "DataSource Connection Results:\n\t$splitconnection[1]\n";
}	
}

sub dbtype {
	my @ARDbmstype=grep(/SQL_DBMS_NAME|KHD_DBMS/i,@ARLogarray) or print "\nDatabase Type: ";
	if ($#ARDbmstype < 0) {
		print " NOT FOUND.\n";
	} else {
		my $sShiftdbmstype=shift(@ARDbmstype);
		my @splitdbmstype=split(/=/,$sShiftdbmstype);
		print "\nDatabase Type:\n\t$splitdbmstype[1]";
	}

}

sub get_khdbatchuse {
my @ARkhdbatch=grep(/$searchkhdbatch/,@ARLogarray) or print "\nKHD_BATCH_USE";
if ($#ARkhdbatch < 0) {
	print " NOT FOUND.\n";
} else {
	my $sShiftkhdbatch=shift(@ARkhdbatch);
	my @splitkhdbatch=split(/set\sto/,$sShiftkhdbatch);
	chomp(@splitkhdbatch);
	print "KHD_BATCH_USE:\n\tSet to $splitkhdbatch[1]\n";
}
}

sub getdbinfo_win {
my $sGetdatabaseinfo_win=undef;
my @ARGetdatabaseinfo_win=grep(/khdxodbc.*getDatabaseInfo/,@ARLogarray) or print "\nDatabase Info ";
if ($#ARGetdatabaseinfo_win < 0) {
	print " NOT FOUND.\n";
}
else {
	print "\nAll Database Information:\n";
	foreach $sGetdatabaseinfo_win (@ARGetdatabaseinfo_win) {
		($sGetdatabaseinfo_win) = $sGetdatabaseinfo_win =~ m/getDatabaseInfo"\)\s(.*?)$/;
		print "$sGetdatabaseinfo_win\n";
	}
	my $sgetDB2CodePage=undef;
	my @ARGetDB2CodePage=grep(/BSS1_GetEnv.*DB2CODEPAGE=/,@ARLogarray) or print "\nDB2CODEPAGE=====================>";
	if ($#ARGetDB2CodePage < 0) {
		print "NOT FOUND\n"
	}
	else {	
	my $shiftmatchdb2codepage = shift(@ARGetDB2CodePage);
	my @db2codepage=split(/DB2CODEPAGE=/,$shiftmatchdb2codepage);
	chomp(@db2codepage);
	my $sdb2codepage=pop(@db2codepage);
	print "\nDB2CODEPAGE===============>\ $sdb2codepage\n";
	}

}
}

sub getdbinfo {
my $sGetdatabaseinfo=undef;
my @ARGetdatabaseinfo=grep(/BSS1_GetEnv"\)\sKHD_/,@ARLogarray) or print "\nDatabase Info ";
if ($#ARGetdatabaseinfo < 0) {
	print " NOT FOUND.\n";
}
else {
	print "\nAll Database Information:\n";
	foreach $sGetdatabaseinfo (@ARGetdatabaseinfo) {
		($sGetdatabaseinfo) = $sGetdatabaseinfo =~ m/BSS1_GetEnv"\)\s(.*?)$/;
		print "$sGetdatabaseinfo\n";
	}
}
}


sub reject {
my $searchrejected=("rejected for timeout reason in stage END_QUEUE");
open (LOG,"<$mostrctlog");
my @ARLogarray =  <LOG>;
close(LOG);

my @ARReject=grep(/$searchrejected/i,@ARLogarray) or my $sreject=("none");
if ($#ARReject >= 0) {
	my $shiftreject=shift(@ARReject);
	chomp($shiftreject);
	$shiftreject=($shiftreject =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	if ($sLocalhostos eq "Windows") {
		print "<<<Solution: Increase KDCFC_RXLIMIT in the WPA configuration file.\thttp://www-01.ibm.com/support/docview.wss?uid=swg21383966 >>>\n\n";
	} else {
		print color 'bold';
		print "<<<Solution: Increase KDCFC_RXLIMIT in the WPA configuration file.\thttp://www-01.ibm.com/support/docview.wss?uid=swg21383966 >>>\n\n";
		print color 'reset';
	}
} 
}

sub utf8 {
my $searchdb2utf8=("encoding is not UTF8");
open (LOG,"<$mostrctlog");
my @ARLogarray =  <LOG>;
close(LOG);

my @ARUtf8=grep(/$searchdb2utf8/i,@ARLogarray) or my $sutf8=("none");
if ($#ARUtf8 >= 0) {
	my $shiftutf8=shift(@ARUtf8);
	chomp($shiftutf8);
	if ($sLocalhostos eq "Windows") {
	print "$shiftutf8\n";
	$shiftutf8=($shiftutf8 =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	} else {
	$shiftutf8=($shiftutf8 =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	print color 'bold';
	print "<<Solution: You need to set the OS environment variable DB2CODEPAGE=1208 for DB2 or NLS_LANG=<NLS_LANGUAGE>_<NLS_TERRITORY>.AL32UTF8 for ORACLE\nConfirm DB2CODEPAGE=1208 using the following commands (replace WAREHOUS and itmuser with appropriate information):\ndb2 connect to WAREHOUS user itmuser\ndb2 get db cfg\n\nThe second command should show the DB2CODEPAGE variable somewhere in the output (use grep or findstr for simplicity).  If the DB2CODEPAGE is not 1208 then change it to 1208 by using the command:\ndb2set DB2CODEPAGE=1208\n\nNOTE: If this is a Windows system, then you must also create an OS environment variable  DB2CODEPAGE and set its value to 1208 (right-click on My Computer -> Properties -> Advanced -> Enviroment Variables -> System Variables -> New).  Windows will need to be restarted for this change to properly take effect.>>>\n\n";
	print color 'reset';
	}
} 
}

sub itm_errors {
my $searchcmsrunning=("Unable to find running CMS");
open (LOG,"<$mostrctlog");
my @ARLogarray =  <LOG>;
close(LOG);

my @ARCms=grep(/$searchcmsrunning/,@ARLogarray) or my $cms=("none");
if ($#ARCms >=0) {
	my $shiftcms=pop(@ARCms);
	chomp($shiftcms);
	$shiftcms=($shiftcms =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	if ($sLocalhostos eq "Windows") {
		print "<<Solution:  Confirm Agent connect to TEMS by running 'tacmd listsystems' at HUB TEMS>>\n\n";
	} else {
		print color 'bold';
		print "<<Solution:  Confirm Agent connect to TEMS by running 'tacmd listsystems' at HUB TEMS>>\n\n";
		print color 'reset';
	}
} 
}

##################################################################################
#####################        DB Errors Subroutines ###############################
##################################################################################

sub err_ora {
unlink("reviewras.oraerr");
open (LOG,"<$mostrctlog");
my @ARLogarray =  <LOG>;
close(LOG);
my @AROraerror=grep(/ORA-\d+/,@ARLogarray);
if ($#AROraerror >= 0) {
	open(ORAERROR,">reviewras.oraerr");
	foreach my $sORAerror(@AROraerror) {
		$sORAerror=($sORAerror =~ /^(.)([\dA-F]+)(\..*)/); 
		printf  ORAERROR "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}	
	close(ORAERROR);
	open(ERRORFILE,"<reviewras.oraerr");
	open(DBERROROUTPUT,">$mostrctlog.reviewras.oraerr");
	while(<ERRORFILE>) {
	s/^\s+$//;
	print DBERROROUTPUT "$_\n";
	}
	close(ERRORFILE);
	close(DBERROROUTPUT);
	if ($sLocalhostos eq "Windows") {
		print "Oracle Errors Found:\n";
		print "Oracle Database Errors stored in $mostrctlog.reviewras.oraerr\n";
	} else {
	print color 'bold red';
	print "Oracle Errors Found:\n";
	print "Oracle Database Errors stored in $mostrctlog.reviewras.oraerr\n";
	print color 'reset';
	}
unlink("reviewras.oraerr");
}
}

sub ora_01034 {
my $searchora01034=("ORA-01034");

open (LOG,"<$mostrctlog");
my @ARLogarray =  <LOG>;
close(LOG);

my @ARora01034=grep(/$searchora01034/,@ARLogarray) or my $ora=("none");

if ($#ARora01034 >= 0) {
	my $shift01034=pop(@ARora01034);
	chomp($shift01034);
	if ($sLocalhostos eq "Windows") {
		print "$shift01034\n";
		print "<<Solution: Have ORACLE DBA confirm Oracle database status.>>\n\n";
	} else {
		print "$shift01034\n";
		print color 'bold';
		print "<<Solution: Have ORACLE DBA confirm Oracle database status.>>\n\n";
		print color 'reset';
	}
} 
}

sub err_db2 {
unlink("reviewras.db2err");
open (LOG,"<$mostrctlog");
my @ARLogarray =  <LOG>;
close(LOG);
my @ARDb2err=grep(/SQL(\d){4}[I-W]|DB2\sSQL\sError/,@ARLogarray);
my $itotdb2err = $#ARDb2err +1;
if ($#ARDb2err >= 0) {
	open(DB2ERR,">reviewras.db2err");
	foreach my $sDB2error(@ARDb2err) {
		$sDB2error=($sDB2error =~ /^(.)([\dA-F]+)(\..*)/); 
		printf  DB2ERR "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}
	close(DB2ERR);
	
	open(ERRORFILE,"<reviewras.db2err");
	open(DBERRORFILE,">$mostrctlog.reviewras.db2err");
	while (<ERRORFILE>) {
		s/^\s+$//;
		print DBERRORFILE "$_\n";
	}
	unlink("reviewras.db2err");
	close(ERRORFILE);
	close(DBERRORFILE);
	print color 'bold red';
	print "DB2 Errors Found:\n";
	print "DB2 Database Errors stored in $mostrctlog.reviewras.db2err\n";
	print color 'reset';
	
} 
}

sub sql1032n {
open (LOG,"<$mostrctlog");
my @ARLogarray =  <LOG>;
close(LOG);
my @ARsql1032n=grep(/SQL1032N|SQL10224N/,@ARLogarray) or my $sql1032n=("none");
if ($#ARsql1032n >= 0) {
	my $shiftsql1032n=pop(@ARsql1032n);
	chomp($shiftsql1032n);
	if ($sLocalhostos eq "Windows") {
		$shiftsql1032n=($shiftsql1032n =~ /^(.)([\dA-F]+)(\..*)/); 
		printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
		print "<<Solution: Start the DB2 database manager using 'db2start'.>>\n\n";
	} else {
		$shiftsql1032n=($shiftsql1032n =~ /^(.)([\dA-F]+)(\..*)/); 
		printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
		print color 'bold';
		print "<<Solution: Start the DB2 database manager using 'db2start'.>>\n\n";
		print color 'reset';
	}
} 
}

#########################################################################################
############################# End of DB Subroutines         #############################
#########################################################################################
sub err_ctx_warehouseproxynotregistered {
my @ARCtx_warehouseproxynotregistered=grep(/failed\swith\sstatus\sCTX_WarehouseProxyNotRegistered/i,@ARLogarray) or my ($sCtx_waehouseproxynotregistered)="none";
if ($#ARCtx_warehouseproxynotregistered >= 10) {
	print "CTX_WarehouseProxyNotRegistered:\n";
	print "More than 10 errors found.\n";
	my $popCtxwarehouseproxynotregistered=pop(@ARCtx_warehouseproxynotregistered);
	print "$popCtxwarehouseproxynotregistered\n";
} else {
	foreach my $sCtx_warehouseproxynotregistered(@ARCtx_warehouseproxynotregistered) {
	print "$sCtx_warehouseproxynotregistered";
	print "^^^^^^Above Error IS CRITICAL^^^^^\n"
	}
}
}

sub err_rpctonode {
@ARRpcerrortonode=grep(/ERROR MESSAGE: \"RPC Error to node/i,@ARLogarray);
if ($#ARRpcerrortonode < 0) {
	$sRpcerrortonode="none";
} elsif ($#ARRpcerrortonode >= 10) {
	print "RPC Error to node errors found:\n";
	print "More than 10 RPC Error to node errors found.\n";
	$sRpcerrortonode=pop(@ARRpcerrortonode);
	$sRpcerrortonode=($sRpcerrortonode =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	#If necessary, write all errors to log file
} else {
	print "RPC Error to node errors found:\n";
	foreach $sRpcerrortonode(@ARRpcerrortonode) {
	$sRpcerrortonode=($sRpcerrortonode =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}
	print "\n";
}
}

sub err_datasource {
@ARDatasourcefailed=grep(/ERROR MESSAGE: \"Connection with Datasource/i,@ARLogarray);
if ($#ARDatasourcefailed < 0) {
	$sDatasourcefailed="none";
} elsif ($#ARDatasourcefailed >= 10) {
	print "Connection with Datasource Errors Found:\n";
	print "More than 10 Connection with Datasource errors found.\n";
	$sDatasourcefailed=pop(@ARDatasourcefailed);
	$sDatasourcefailed=($sDatasourcefailed =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	print "\n";
} else {
	foreach $sDatasourcefailed(@ARDatasourcefailed) {
	print "Connection with Datasource Errors Found:\n";
	$sDatasourcefailed=($sDatasourcefailed =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	print "\n";
	}
}
}

sub err_ctx_odbcerror {
my @ARCtx_odbcerrorlist=grep(/failed\swith\sstatus\sCTX_ODBCError/i,@ARLogarray) or my ($sCtx_obcerror)="none";
if ($#ARCtx_odbcerrorlist >= 10) {
	print "ODBC Errors Found:\n";
	print "More than 10 ODBC errors found.\n";
	my $popCtxodbcerror=pop(@ARCtx_odbcerrorlist);
	print "$popCtxodbcerror\n";
} else {
	foreach my $sCtx_odbcerror(@ARCtx_odbcerrorlist) {
	print "$sCtx_odbcerror\n";
	}
}
}

sub err_ctx_init {
my @ARCtx_initlist=grep(/CTX_InitializationFailed/i,@ARLogarray) or my ($sCtx_init)="none";
if ($#ARCtx_initlist >= 10) {
	print "CTX_Initialization Errors Found:\n";
	print "More than 10 CTX_Initialization errors found.\n";
	my $popCtxinit=pop(@ARCtx_initlist);
	print "$popCtxinit\n";
} else {
	foreach my $sCtx_init(@ARCtx_initlist) {
	print "$sCtx_init\n";
	}
}
}

sub err_ctx_getcurrentcms {
my @ARCtx_getcurrentcms=grep(/failed\swith\sstatus\sCTX_GEtCurrentCMSAddress/i,@ARLogarray) or my ($sCtx_getcurrentcms)="none";
if ($#ARCtx_getcurrentcms >= 10) {
	print "CTX CMS Errors Found:\n";
	print "More than 10 CTX CMS errors found.\n";
	my $popCtxgetcurrentcms=pop(@ARCtx_getcurrentcms);
	print "$popCtxgetcurrentcms\n";
} else {
	foreach my $sCtx_getcurrentcms(@ARCtx_getcurrentcms) {
	print "$sCtx_getcurrentcms\n";
	}
}
}

sub err_219 {
my @ARErr219list=grep(/Error\s219\shappened\s(.*?)\)/i,@ARLogarray);
#my @ARErr219list=grep(/Error\s219\shappened\s(.*?)\)$/i,@ARLogarray);
if  ($#ARErr219list < 0) {
	my $sErr219=("none");
} elsif ($#ARErr219list >= 10) {
	print "\nError 219 messages:\n";
	my $popErr219=pop(@ARErr219list);
	open (INSERTS,">reviewras.err219");
	foreach my $sErrraw1(@ARErr219list) {
		$sErrraw1=($sErrraw1 =~ /^(.)([\dA-F]+)(\..*)/); 
		printf INSERTS "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}
	close(INSERTS);
	open(INSERTFILE,"<reviewras.err219");
	open(OUTPUTFILE,">$mostrctlog.reviewras.err219");
	while (<INSERTFILE>) {
	s/^\s$//;
	print OUTPUTFILE "$_";
	}
	unlink("reviewras.err219");
	close("INSERTFILE");
	close("OUTPUTFILE");
	print "More than 10 \"Error 219\"  found in RAS log.\n";
	print "Error 219 messages stored in $mostrctlog.reviewras.err219\n";
	print ">>>> If WPA connects to MS-SQL database, check SQL_IDENTIFIER_QUOTE_CHAR.  If the value is set to SQL_IDENTIFIER_QUOTE_CHAR  = \" \"\n";
	print "MSSQL DBA must change this value either at the ODBC connection used by WPA or within the MS-SQL database <<<<\n\n";
	$popErr219=($popErr219 =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
} else {
	foreach my $sErrraw(@ARErr219list) {
	$sErrraw=($sErrraw =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}
} 
}

sub err_connectionlost {
my @ARConnectionlost=grep(/Connection\sfailure:|lost:/i,@ARLogarray) or my $sConnect=("none");
if ($#ARConnectionlost < 0) {
	my $sConnectlost=("none");
} elsif ($#ARConnectionlost >= 10) {
	print "\nConnection Lost Errors:\n";
	my $popConnectionlost=pop(@ARConnectionlost);
	open (INSERTS,">reviewras.connectionlost");
	foreach my $sConnlost(@ARConnectionlost) {
		$sConnlost=($sConnlost =~ /^(.)([\dA-F]+)(\..*)/); 
		printf INSERTS "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}
	close(INSERTS);
	open(INSERTFILE,"<reviewras.connectionlost");
	open(OUTPUTFILE,">$mostrctlog.reviewras.connectionlost");
	while(<INSERTFILE>) {
	s/^\s$//;
	print OUTPUTFILE "$_";
	}
	close("INSERTFILE");
	unlink("reviewras.connectionlost");
	close("OUTPUTFILE");
	print "More than 10 \"Connection failure/lost\" errors found in RAS log.\n";	
	print "Connection lost messages stored in $mostrctlog.reviewras.connectionlost\n";
	$popConnectionlost=($popConnectionlost =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
} else {
	print "\nConnection Lost Errors:\n";
	foreach my $sConnect(@ARConnectionlost) {
	$sConnect=($sConnect =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}
	print "\n";
} 
}

sub err_createrouterequest {
my @ARCreateroute=grep(/\sfailed\sin\screaterouterequest,\s/i,@ARLogarray) or my $sCreateroute=("none");
if ($#ARCreateroute < 0) {
	my $sCreateroute=("none");
} elsif ($#ARCreateroute >=10) {
	print "\nExport Failure Errors:\n";
	my $popCreateroute=pop(@ARCreateroute);
	open (INSERTS,">reviewras.createroute");
	foreach my $sCreateroute(@ARCreateroute) {
		$sCreateroute=($sCreateroute =~ /^(.)([\dA-F]+)(\..*)/); 
		printf INSERTS "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}
	close(INSERTS);
	open(INSERTFILE,"<reviewras.createroute");
	open(OUTPUTFILE,">$mostrctlog.reviewras.createroute");
	while(<INSERTFILE>) {
	s/^\s$//;
	print OUTPUTFILE "$_";
	}
	close("INSERTFILE");
	unlink("reviewras.createroute");
	close("OUTPUTFILE");
	print "More than 10 \"failed in CreateRouteRequest\" errors found in RAS log.\n";	
	$popCreateroute=($popCreateroute =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	print "\nMessages stored in $mostrctlog.reviewras.createroute\n";
} else {
	print "\nFailed in CreateRouteRequest Errors:\n";
	foreach my $sCreateroute(@ARCreateroute) {
	$sCreateroute=($sCreateroute =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}
	print "\n";
} 
}



# Common ITM RAS Subroutines  
sub check_filename {
if ((-e $mostrctlog) && (-T $mostrctlog)) {
	chomp $mostrctlog;
} elsif (-z $mostrctlog) {
	print "File $mostrctlog is 0 bytes\n";
	exit (1);
} elsif (!-e $mostrctlog) {
	print "File $mostrctlog does not exists\n";
	exit (-1);
} elsif (!-r $mostrctlog) {
	print "Permission denied on access of $mostrctlog\n";
	exit (-1);
} else {
	print "Cannot find $mostrctlog.  Confirm RAS log exists.\n\n";
	exit (2);
}	
}

sub get_cms_connectdate {
my @ARCmssuccess=grep(/connected\sto\sCMS/i,@ARLogarray) or print "Did not find a successful TEMS connection within log.\n";
if ($#ARCmssuccess >=0 ) {
	my $popcmssuccess=pop(@ARCmssuccess);
	chomp($popcmssuccess);
	chomp(@ARCmssuccess);
	my @ARCmssuccess=split(/Successfully/,$popcmssuccess);
	my ($sCmssuccesstime)=$ARCmssuccess[1];
	chomp($sCmssuccesstime);
	print "$sCmssuccesstime\n Last Successful Connection Date:\t";
	my $sConvertcmssuccess=($popcmssuccess =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s)\n", $1, scalar(localtime(oct("0x$2")));
} 
}

sub get_compdriverlvl {
my @ARcomponentmatch= grep(/$searchitmcomponent/, @ARLogarray);
my @ARdrivermatch= grep(/.\.(\w){4}\s+$searchitmdriver/, @ARLogarray);

foreach $scomponentmatch (@ARcomponentmatch) {
	my @ARcompsplit=split(/Component:/,$scomponentmatch);
        chomp(@ARcompsplit);
	$ARcompsplit[1] =~ s/\s//g;
	if ($sLocalhostos eq "Windows") {
        	print "$ARcompsplit[1]\t";
        	my $sDriver=substr($ARdrivermatch[$iforloop],15,35);
		chomp($sDriver);
		print "$sDriver\n";
        	$iforloop++;
	} else {
		if ($ARcompsplit[1] eq "khd") {
		print color 'bold green';
		print "$ARcompsplit[1]\t";
        	my $sDriver=substr($ARdrivermatch[$iforloop],15,35);
		chomp($sDriver);
		print "$sDriver\n";
		print color 'reset';
        	$iforloop++;
		} else {
        	print "$ARcompsplit[1]\t";
        	my $sDriver=substr($ARdrivermatch[$iforloop],15,35);
		chomp($sDriver);
		print "$sDriver\n";
        	$iforloop++;
		}
	}
}
}

sub get_EOF {
open (LOG,"<$mostrctlog");
my @ARLogarray =  <LOG>;
close(LOG);
# Avoid popping @ARLogarray, as the pop will remove last line of @ARLogarray
#my @ARPoplogarray=pop(@ARLogarray);
my $sPoplogarray=$ARLogarray[$#ARLogarray];
my @AREof=grep(/^[\(|\+]/,$sPoplogarray);
#my @AREof=grep(/^\(/,$sPoplogarray);
	if ($#AREof < 0) {
		print "\n\t********** \tEnd of file reached\t **********\n";
		print "$sPoplogarray"
	}	
}
