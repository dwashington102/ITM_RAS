#!/usr/bin/perl -w
# tepsreview.pl
# Date: 2010/08/21
#------------------------------------------------------------------------------
# Licensed Materials - Property of IBM (C) Copyright IBM Corp. 2010, 2010
# All Rights Reserved US Government Users Restricted Rights - Use, duplication
# or disclosure restricted by GSA ADP Schedule Contract with IBM Corp
#------------------------------------------------------------------------------
# Script is AS-IS and not supported by IBM Support.
#------------------------------------------------------------------------------
#
# Script will parse TEPS RAS logs. Gathering useful information, locate known errors, and
# provide solutions for known errors
# Author David Washington
# washingd@us.ibm.com
#################################################################################
#
# Revision History:
# Revision 2.16 2016/09/14
# 	Modified db2_err to only locate SQL\d{4} and SQL\d{5} to find messages that end with C, N, or W
# Revision 2.15 2016/08/24
# 	Added search to detect GSKKM_GetKeyItemListByLabel errors. err_get_keyitems()
# Revision 2.14 2016/05/12
# Changed err_warehousesumprune grep statement
# Previous grep: my @ARWarehousesumprune=grep(/Error\sretrieving\sSumm/,@ARLogarray);
# New grep: my @ARWarehousesumprune=grep(/Error\sretrieving\sSumm|exception\scaught\sdetermining\scolumn\ssize\sfor\sWAREHOUSESUMPRUNE/,@ARLogarray);
# Revision 2.13 2016/03/04
#	Added search to detect dynamic trace setting change "KBBRA_ChangeLogging"
# Revision 2.12 2016/02/05
# 	Added search for "Conversation timeout: "<protocol>:#<HUB TEMS IP Address>:1918", 1C010008:00000000"
# Revision 2.11  2015/05/16
# 	Added search for "Error retrieving ....table"  (err_warehousesumprune()) indicating problems with TEPS -> DWH database
# Revision 2.10  2014/09/29
#   Updated db2_errors() to capture DB2 SQL errors that included 5 digits after "SQL"
# Revision 2.0.9 2014/09/16
# 	Added search for SDA WARNING regarding KFWAPPSUPPORT table
# Revision 2.0.7 2013/12/13
# 		Added search for add_listener
# Revision 2.0.6 2013/07/30
#		Added search for CANDLEHOME
# Revision 2.0.5 2013/04/26
#	Added search for "Process ID"
# Revision 2.0.4 2013/02/16
#	Added search for get_kfw1100i - confirming how many users are connected to the TEPS
#
# Revision 2.0.3 2012/08/19
#	Added search for Nofiles Descriptor Setting

# Revision 2.0.2 2012/08/08:
# 	Change get_cnpior() to only grep writeIORFILE
#
# Revision 2.0.1 2012/03/20:
#	Add err_describedatasources()
#
# Revision 2.0 2011/02/28:
#	Changed err_ipaddrchange() to write errors to log file when more than 10 messages are found. Pointed to solution.
#
# Revision 1.9 2011/02/07:
#	Corrected bug: d-20110207a
#	Changed if ($sKfwdsn eq "TEPS0") {
#	to
#	if ($sKfwdsn =~ m/TEPS0/) {

# Revision 1.8 2010/11/08:
# 	Changed my @startup=grep(/$searchitmstartteps\ \*\*/, @ARLogarray); to narrow search for  "KFW1020I **"
#	Added err_ipaddrchange()
#
# Revision 1.7 2010/11/01
#	Added @ARKdebinterfacelist
#
# Revision 1.6 2010/10/10
#	Correct bug 20101007a using:
#	my @ARTemsconnectionlist=grep(/\sKFW1011I\s\w+:\s|\sKFW1012I\s\w+:\s/i,@ARLogarray);
#
# Revision 1.5 2010/10/10
#	changed get_EOF() replaced
#	> my @AREof=grep(/^\(/,$sPoplogarray);
#
# Revision 1.4 2010/09/26
#	added get_cnpior()
# 	changed get_compdriverlvl()
#	changed get_EOF() to get last element of @ARLogarray rather than pop @ARLogarray
# 	Replaced references to @label[1] in else{} when printing, with /m for theses arrays:
#	> @ARkdcfamilies, @ARPortassign, @ARewas, @ARjvm, @ARFips, @itmmatchtype, @itmmatchdate, @itmmatchtime, @itmmatchusername
#
# Revision 1.3 2010/09/15
#	added get_temsconnection() - gathers TEPS to TEMS connection information
#	added check_filename() - confirms file passed is valid
#	added err_corba_systemexception () - detects RAS_CORBA errors
#	changed output for portshare_error() - Windows checking enabled
#
# Revision 1.2 2010/09/13
#	added get_tdwconnection()
#	added err_connectionlost()
#	added 0 byte size checking (-z $mostrctlog)
#	added access permission checking (!-r $mostrctlog)
#
# Revision 1.1 2010/08/23
#		added err_jvm()
#
# Revision 1.0 2010/02/01					
#################################################################################
# Defects Found:
# 2010/10/07:
# d-20101007a - Use of uninitialized value $sTemsconnect
# Any instance of KFW1011I or KFW1012I is found using grep
#	my @ARTemsconnectionlist=grep(/KFW1011I|KFW1012I/i,@ARLogarray);
#
# 2011/02/07:
# d-20110207a - if ($sKfwdsn eq "TEPS0") { failed to correctly detect KFW_DSN setting
# in TEPS log.
#################################################################################

use strict;
use warnings;
use Term::ANSIColor;
use Cwd;

##################################################################################
#######################     Set Variables      ###################################
##################################################################################
my $currentdir = cwd;
my $iforloop =0;
my $iforloopnic =1;

# undefined variables
my $sHost=undef;
my $sStarttime=undef;
my $sIpaddrsplt=undef;
my $scomponentmatch=undef;
my $itotdb2err=undef;
my $sHextime=undef;
my $sSysT=undef;
my $sSysType=undef;
my $sStartTime=undef;
my $sPortassign=undef;
my $sKdhslqm=undef;
my $sGetkey=undef;
undef my @ARctirahost;
undef my @ARtepserrors;

##################################################################################
#######################     Search String Variables ##############################
##################################################################################
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

# Searches used to extract network and TEMS information.
my $searchitmipaddr=("source=");
my $searchkdc=("KDC_FAMILIES=");
my $searchagentport=("KDEBP_AssignPort");
my $searchhttpkdhsqlqm=("kdhslqm.*add_listener.*listening");
my $searchctirahostname=("CTIRA_HOSTNAME");
my $searchkdebinterface=(" KDEB_INTERFACELIST=");
my $searchitmcms=("CT_CMSLIST");

# Searches used to extract eWAS and JVM information.
my $searchewas=("KFW_USE_EMBEDDED");
my $searchjvm=("KFW_STARTJVM");
my $searchfips=("KFW_FIPS_ENFORCED");

# Searches for jar files loaded by TEPS
my $searchctjdbc=("KFW_JVM__CTJDBC__CLASSPATH=");
my $searchkfwdsn=(" KFW_DSN=");

# Search for TEPS startup message
my $searchitmstartteps=("KFW1020I");

# Common errors found in RAS logs
my $searchcmsrunning=("Unable to find running CMS");

##################################################################################
#######################     End Search String Variables ##########################
##################################################################################

#################################################################################
#####################      Get LocalHost OS      ################################
#################################################################################
my $sRawOS=$^O;
my $sLocalhostos=substr($sRawOS,0,5);

if ($sLocalhostos eq "MSWin") {
        $sLocalhostos=("Windows");
} else {
	$sLocalhostos=$sRawOS;
}
#################################################################################

##################################################################################
#######################        Main Program    ###################################
##################################################################################
my $mostrctlog=$ARGV[0] or die "Usage: tepsreview.pl [RAS LOG]\n\n";
check_filename();
open (LOG,"<$mostrctlog");
our @ARLogarray =  <LOG>;
close(LOG);
print "\n#######################################################\n";
print "\t$mostrctlog\n";
print "#######################################################\n";

my @itmmatchdebug = grep(/$searchitmdebug/, @ARLogarray) or print "KBB_RAS1 setting not found.\n";
if ($#itmmatchdebug < 0 ) {
	print "Confirm KBB_RAS1 setting is enabled.\n";
}
else {
	my $shiftmatchdebug = shift(@itmmatchdebug);
	my @debuglevel=split(/KBB_RAS1[=|:]/,$shiftmatchdebug);
	chomp(@debuglevel);
	my $rasdebug=pop(@debuglevel);
	print "\n#######################################################\n";
	print "Debug Setting (KBB_RAS1): $rasdebug\n";
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
}
else {
	my $shiftmatchsystem = shift(@itmmatchsystem);
	# Not sure what or why this split was done, but if it's not broken - don't fix it.
	my @systemname=split(/KBB_RAS1:/,$shiftmatchsystem);
	my $sString="@systemname";
	($sHost) = $sString =~ m/System Name:\s+(.*?)\s+/;
	print "HostName: $sHost\n";
}

my @itmmatchtype = grep(/$searchitmsystemtype/, @ARLogarray) or print "System Type:\t";
if ($#itmmatchtype < 0 ) {
	print " NOT FOUND\n";
}
else {
	$_=shift(@itmmatchtype);
	($sSysType) = $_ =~ m/System\sType:\s(.*?)\s+?/;
	if ($sSysType =~ m/Linux/) {
		($sSysType) =~ s/;/- Kernel Version: /;
		print "System Type: $sSysType\n";
	} else {
		print "System Type: $sSysType\n";
	}
}

my @itmmatchdate = grep(/$searchitmstartdate/, @ARLogarray) or print "Start Date:\t";
if ($#itmmatchdate < 0) {
	print " NOT FOUND\n";
}
else {
	$_=shift(@itmmatchdate);
	my ($sStartdate) = $_ =~ m/Start\sDate:\s(.*?)\s+?/;
	print "Start Date: $sStartdate\n";
}

my @itmmatchtime = grep(/\d+\s+$searchitmstarttime/, @ARLogarray) or print "Start Time:\t";
if ($#itmmatchtime < 0) {
	print " NOT FOUND\n";
}
else {
    my ($shiftmatchtime) = shift(@itmmatchtime);
	($sStartTime) = $shiftmatchtime =~ m/Start\sTime:\s(.*?)\s+?/i;
	print "Start Time: $sStartTime\n";
}

my @itmmatchusername=grep(/$searchusername/,@ARLogarray) or my $sUsernamenull=("NOT FOUND");
if ($#itmmatchusername < 0) {
	$sUsernamenull=("NOT FOUND");
} else {
	my $shiftmatchusername=shift(@itmmatchusername);
	my ($sUsername) = $shiftmatchusername =~ m/User\sName:\s(.*?)\s+?/i;
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
print "Network Information and TEPS Configuration:\n";
my @ARipaddrmatch = grep (/\.\d+:\s$searchitmipaddr/,@ARLogarray) or print "IP address:\t";
if ($#ARipaddrmatch < 0) {
	print " NOT FOUND\n";		
} else {
	foreach	my $sIpaddrstr (@ARipaddrmatch) {
	($sIpaddrsplt) = $sIpaddrstr =~ m/.\w\s+(.*?):\s+source/;
	print "Network Interface Card[$iforloopnic] (source=): $sIpaddrsplt\n";
	$iforloopnic++;
	}	
}

my @ARKdebinterfacelist=grep(/$searchkdebinterface/,@ARLogarray);
if ($#ARKdebinterfacelist < 0) {
	my $skdebinterface=("KDEB_INTERFACELIST NOT SET");
} else {
	my $sShiftkdebinterfacelist=shift(@ARKdebinterfacelist);
	my @ARKdebintersplit=split(/KDEB_INTERFACELIST=/,$sShiftkdebinterfacelist);
	chomp(@ARKdebintersplit);
	print "\nKDEB_INTERFACELIST=$ARKdebintersplit[1]\n";
}


my @ARkdcfamilies = grep (/$searchkdc/,@ARLogarray) or print "KDC_Families and Port Assignment:\t";
if ($#ARkdcfamilies < 0) {
	print " NOT FOUND\n";
}
else {
	$_=shift(@ARkdcfamilies);
	my ($sKdcfamilies) = $_ =~ m/=KDC_FAMILIES="(.*?)"/;
	print "\nKDC_FAMILIES setting:\n$sKdcfamilies\n";
}

my @ARPortassign=grep(/$searchagentport\"\)\s\w(.*?)\sbound\sto\sport\s/, @ARLogarray) or print "\nPort Assignment ";
if ($#ARPortassign < 0) {
	print " NOT FOUND\n";
}
else {
	print "\nPort Agent is connected to (KDEBP_AssignPort):\n";
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



#my @ARKdebinterfacelist=grep(/$searchkdebinterface/,@ARLogarray);
#if ($#ARKdebinterfacelist >= 0) {
#	my $sKdebinterfacelist=pop(@ARKdebinterfacelist);
#	($sKdebinterfacelist) = $sKdebinterfacelist =~ m/KDEB_INTERFACELIST=\"(.*?)\"/;
#	print "\nKDEB_INTERFACELIST: $sKdebinterfacelist\n";
#}
#############################################
###Specific to only the TEPS1 RAS log file###
#############################################

my @ARKfwdsnlist=grep(/$searchkfwdsn/, @ARLogarray) or print "\nKFW_DSN value";
if ($#ARKfwdsnlist < 0) {
	print " NOT FOUND.  Confirm TEPS Database Type.\n";
} else {
	my $shiftkfwdsnlist=shift(@ARKfwdsnlist);
	my @ARKfwdsn=split(/KFW_DSN=/,$shiftkfwdsnlist);
	chomp(@ARKfwdsn);
	my $sKfwdsn=pop(@ARKfwdsn);
	chomp $sKfwdsn;
	#$sKfwdsn =~ s/"//g;

	if ($sKfwdsn =~ m/TEPS0/) {
	 print "\nTEPS Database Type (KFW_DSN): Derby\n";
	} elsif ($sKfwdsn =~ m/MSSQL/) {
	 print "\nTEPS Database Type (KFW_DSN): MSSQL\n";
	} elsif (($sKfwdsn eq "TEPS"||"TEPS2"||"TEP"||"CNPS"||"CNP")){
	 print "\nTEPS Database Type (KFW_DSN): DB2\n";
	} else {
	 print "\nTEPS Database Type: NOT FOUND\n";
	}
}

print "\nEWAS and Crypto Settings:\n";
my @ARewas=grep(/$searchewas/,@ARLogarray) or print "EWAS Setting $searchewas ";
if ($#ARewas < 0 ) {
	print " NOT FOUND.\n";
}
else {
	$_=shift(@ARewas);
	my ($sEwas) = $_ =~ m/_GetEnv"\)\s(.*?)$/;	
	chomp($sEwas);
	print " $sEwas","\n";
}

my @ARjvm=grep(/$searchjvm/,@ARLogarray) or print "JVM Setting $searchjvm ";
if ($#ARjvm < 0) {
	print " NOT FOUND.\n";
}
else {
	$_=shift(@ARjvm);
	my ($sJvm)= $_ =~ m/_GetEnv"\)\s(.*?)$/;
	print " $sJvm\n";
}

my @ARFips=grep(/$searchfips/i,@ARLogarray) or print "KFW_FIPS_ENFORCED ";
if ($#ARFips < 0) {
	print "NOT FOUND.\n";
} else {
	$_=shift(@ARFips);
	my ($sFips)= $_ =~ m/_GetEnv"\)\s(.*?)$/;
	print " $sFips\n";
}

my @ARctjdbc=grep(/$searchctjdbc/,@ARLogarray) or print "\nKFW_JVM__CTJDBC_CLASSPATH ";
if ($#ARctjdbc < 0) {
	print "NOT FOUND.\n";
}
else {
	chomp(@ARctjdbc);
	my $sCtjdbc="@ARctjdbc";
	my @ARsplitctjdbc=split(/GetEnv\"\)/,$sCtjdbc);
	chomp(@ARsplitctjdbc);
	print "\nIf TEPS connects to Oracle data warehouse, confirm correct Oracle jar file is specified here:";
	print "\nIf TEPS connects to MSSQL data warehouse, confirm correct MSSQL jar file is specified here:";
	print "\n$ARsplitctjdbc[1]\n";
}
# Gather TDW connection information
get_cnpior();
get_tdwconnection();
err_describedatasources();
err_warehousesumprune();

print "#######################################################\n";

# Confirms TEPS is ready for connections
print "\n#######################################################\n";
print "Checking for Startup Complete...\n";
my @startup=grep(/$searchitmstartteps\ \*\*/, @ARLogarray) or print "\"Waiting for request\" not shown in log.\n";
if ($#startup < 0) {
	print ">>>Must confirm  TEPS is ready for logins.<<<<\n";
}
else {
        print ">>>>>>>>>>>>>>>>>>>>>>TEPS IS READY FOR LOGIN REQUESTS<<<<<<<<<<<<<<<<<<<<\n";
	my $sTepsup=shift(@startup);
	$sTepsup=($sTepsup =~ /^(.)([\dA-F]+)(\..*)/);
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	get_kfw1048i();
}

my @itmcmsfound=grep(/$searchitmcms/,@ARLogarray)  or print "\nTEPS connection to TEMS ";
if ($#itmcmsfound < 0) {
	print " NOT FOUND. >>> Confirm TEPS connection to TEMS is established.<<<\n";
}
else {
	my $itmcmsstring=shift(@itmcmsfound);
	my @ARcmssplit=split(/CT_CMSLIST=/,$itmcmsstring);
	chomp(@ARcmssplit);
	my $sCMSconnect=$ARcmssplit[1];
	$sCMSconnect =~ s/"//g;
	print "\nTEPS is configured to connect to TEMS using: $sCMSconnect\n";
	get_temsconnection();
	get_kfw1100i();
}
print "\n#######################################################\n";

print "\n#######################################################\n";
print "Components and Driver Levels:\n";
get_compdriverlvl();
print "\nThe kcj component represents the TEPS\n";
print "\nTo match driver levels to ITM 6 versions, see URL:\nhttp://www-01.ibm.com/support/docview.wss?uid=swg27008514\n";
print "#######################################################\n";

print "\n#######################################################\n";
print "ERROR Messages Found in RAS LOG:\n";
unlink("$mostrctlog.reviewras.err");

# Calling subroutines to locate errors in log
err_get_keyitems();
sda_warning();
err_jvm();
err_ipaddrchange();
itm_errors();
jdbcservice_message();
check_kfwmsenu();
check_bss1getenv();
tepsdbconnect_error();
portshare_error();
d102362_error();
sql0443n_error();
sql1032n_error();
sql1224n_error();
sql30082n_error();
db2_errors();
ora_errors();
teps_errors();
err_connectionlost();
err_corba_systemexception();
err_aix_IV77462();

if (-e "$mostrctlog.reviewras.err") {
	if ($sLocalhostos eq "Windows") {
	print "\nError checking completed for $mostrctlog.\nCommon TEPS Error(s) stored in $mostrctlog.reviewras.err\n";
	} else {
	print color 'bold';
	print "\nError checking completed for $mostrctlog.\nCommon TEPS Error(s) stored in $mostrctlog.reviewras.err\n";
	print color 'reset';
	}
} else {
	print "\nError checking completed for $mostrctlog.\n Confirm TEPS came online by checking the Startup section above.\n";
}
print "\n#######################################################\n";
get_EOF();

print "\n#######################################################\n";
   print "Do you want to convert HEX timestamps in $mostrctlog (type \"yes\" or \"no\"):  \t";
   my $sCONVERT=<STDIN>;
   chomp($sCONVERT);
   if (($sCONVERT eq "yes")||($sCONVERT eq "YES")) {
   	system ("/usr/local/bin/convertras.pl $mostrctlog");
   }
print "\n#######################################################\n";
print "Review of $mostrctlog completed.\n";
print "\n#######################################################\n";
exit(0);

##################################################################################
#######################        Subroutines     ###################################
##################################################################################
sub check_filename {
if (-z $mostrctlog) {
	print "File $mostrctlog is 0 bytes\n";
	exit (1);
} elsif (!-e $mostrctlog) {
	print "File $mostrctlog does not exists\n";
	exit (-1);
} elsif (!-r $mostrctlog) {
	print "Permission denied on access of $mostrctlog\n";
	exit (-1);
} elsif  ((-e $mostrctlog) && (-T $mostrctlog))  {
	chomp $mostrctlog;
	return(0);
} else {
	print "Unable to process $mostrctlog.\n";	
}
}

sub err_get_keyitems {
my @ARGetkeyitemlist=grep(/Failed\ in\ GSKKM_GetKeyItemListByLabel/,@ARLogarray);
if ($#ARGetkeyitemlist < 0) {
	my $sGetkeylist=("none");
	return(0);
} else {
	my $popGetkeyitemlist=pop(@ARGetkeyitemlist);	
	print "\n<<<<<<<<<<< CRITICAL:  TEPS Fails to start >>>>>>>>>>>>>>>";
	print "\n$popGetkeyitemlist";
	print ">>> Solution:  http://www-01.ibm.com/support/docview.wss?uid=swg21589328 <<<\n";
}
}

sub err_ipaddrchange {
my @ARIpaddrchange=grep(/IP ADDR CHANGE/,@ARLogarray);
if ($#ARIpaddrchange < 0) {
	my $sIpaddrchange=("none");
} elsif ($#ARIpaddrchange >= 10) {
	print "\nAgent Servers causing Navigator Updates Pending Messages:\n";
	my $popIpaddr=pop(@ARIpaddrchange);
	open (INSERTS,">reviewras.ipaddrchange");
	foreach my $sIpaddrchange(@ARIpaddrchange) {
		$sIpaddrchange=($sIpaddrchange =~ /^(.)([\dA-F]+)(\..*)/);
		printf INSERTS "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}	
	close(INSERTS);
	open(INSERTFILE,"<reviewras.ipaddrchange");
	open(OUTPUTFILE,">$mostrctlog.reviewras.ipaddrchange");
	while(<INSERTFILE>) {
	s/^\s$//;
	print OUTPUTFILE "$_";
	}
	close("INSERTFILE");
	unlink("reviewras.ipaddrchange");
	close("OUTPUTFILE");	
	print "More than 10 \"IP ADDR CHANGE\" messages found in RAS log.\n";
	$popIpaddr=($popIpaddr =~ /^(.)([\dA-F]+)(\..*)/);
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	if ($sLocalhostos eq "Windows") {
	print "Messages stored in $mostrctlog.reviewras.ipaddrchange\n";
	print ">>>>>> Solution: http://www-01.ibm.com/support/docview.wss?uid=swg21424789  <<<<<<<<<<<\n";
	} else {
		print color 'bold';
		print "Messages stored in $mostrctlog.reviewras.ipaddrchange\n";
		print ">>>>>> Solution: http://www-01.ibm.com/support/docview.wss?uid=swg21424789  <<<<<<<<<<<\n";
		print color 'reset';
	}
	print "\n";
} else {
	print "\nAgent Servers causing Navigator Updates Pending Messages:\n";
	foreach my $sIpaddrchange(@ARIpaddrchange) {
	$sIpaddrchange=($sIpaddrchange =~ /^(.)([\dA-F]+)(\..*)/);
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}
	if ($sLocalhostos eq "Windows") {
	print ">>>>>> Solution: http://www-01.ibm.com/support/docview.wss?uid=swg21424789  <<<<<<<<<<<\n";
	} else {
		print color 'bold';
		print ">>>>>> Solution: http://www-01.ibm.com/support/docview.wss?uid=swg21424789  <<<<<<<<<<<\n";
		print color 'reset';
	}
	print "\n";
}
}

sub err_describedatasources {
my @ARDescribedatasource=grep(/unable\sto\sestablish\sdatabase\sconnection\sto/i,@ARLogarray) or my $sDescribedatasource=("none");
	if ($#ARDescribedatasource >= 0) {
		print "\nErrors in RAS log indicate the TEPS failed to connect to the data warehouse.\n";
		my $sDescribedatasource=pop(@ARDescribedatasource);
		chomp($sDescribedatasource);
		$sDescribedatasource=($sDescribedatasource =~ /^(.)([\dA-F]+)(\..*)/);
		printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	} else {
		$sDescribedatasource=("none");
	}
}

sub get_cnpior {
#my @ARCnpior=grep(/writeIORFILE\"\)\sInterface\s=/i,@ARLogarray);
my @ARCnpior=grep(/writeIORFILE\"\)\s/i,@ARLogarray);
if ($#ARCnpior >= 0 ) {
	my ($sCnpior) = pop(@ARCnpior);
	#($sCnpior) = $sCnpior =~ m/IOR:(.*?)>/;
	my @ARIor=split(/\s=\s/,$sCnpior);
	chomp(@ARIor);
	my $sIor=pop(@ARIor);
	print "\nTEPS IOR: $sIor\n";
}
}

sub err_jvm {
my $popARLogarray=pop(@ARLogarray);
my @ARJvmerr=grep(/Exiting\sJVM/i,$popARLogarray);
if ($#ARJvmerr >= 0) {
	my @AROscheck=grep(/System\sType:\sLinux/i,@ARLogarray);
	if ($#AROscheck >= 0) {
		print "Last line of TEPS RAS log:\n";
		$popARLogarray=($popARLogarray =~ /^(.)([\dA-F]+)(\..*)/);
		printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
		if ($sLocalhostos eq "Windows") {
		print "<<<Solution:  If TEPS is installed on Suse 11 see d-133751.>>>\n";
		print "<<<Solution: http://www-01.ibm.com/support/docview.wss?uid=swg21315802 >>>\n\n";
		} else {
		print color 'bold';
		print "<<<Solution:  If TEPS is installed on Suse 11 see d-133751.>>>\n";
		print "<<<Solution: http://www-01.ibm.com/support/docview.wss?uid=swg21315802 >>>\n\n";
		print color 'reset';
		}
	}
}
}

sub get_kfw1048i {
my @ARKfw1048i=grep(/KFW1048I/,@ARLogarray);
if ($#ARKfw1048i >= 0) {
	foreach my $kfw1048i(@ARKfw1048i) {
	$kfw1048i=($kfw1048i =~ /^(.)([\dA-F]+)(\..*)/);
	print "\nShutdown of TEPS found in log after the TEPS came online:\n";
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}
}
}

sub teps_errors {
my @ARTepserrors=("rc=209","KFWITM396E","Table not found","EXCEPTION: ::CTDataBus::ProcessingError - _data->executeRequest","Error: definition is null","EXCEPTION: ::CTReport::Manager::DefinitionUnavailable - executeRequest","CTQuery::ProcessingError","KFW1004E","KFW1005E","KFW1014E","KFW1016E","KFW1027E","KFW1028E","KFW1032E","KFW1036E","KFW1037E","KFW1041E","KFW1049E","KFW00392E","KFW00393E","KFW00396E","KFW00398E","KFW1505E","KFW1552E","KFW1553E","KFW1572E","KFW1573E","KFW00478E","Bad Userid","KFW1103I Invalid user ID","borland.lic is corrupted","KDE1_STC_CONNECTIONFAILURE","Data Warehouse is not configured properly","No Warehouse found for","SQL1_OpenRequest failed","ICC initialization failed","Unable to establish database connect","Specified driver","User ID or password is invalid","Failed when validating user through Authenication service","Create Path Error","CORBA User Exception has occurred","no data in KFWDBVER","SQL1_CloseRequest failed rc=","error in HTTP request","GSK_ERROR_BAD_KEYFILE_PASSWORD",
"Unknown exception - double exception");

unlink("rawreviewras.tepserr");
unlink("reviewras.tepserr");
foreach my $sTepserror(@ARTepserrors) {
	my @ARErrlist=grep(/$sTepserror/i,@ARLogarray);
	open(TEPSERR,">>rawreviewras.tepserr");
	print TEPSERR "@ARErrlist\n";
}
close(TEPSERR);
open(ERRORFILE,"<rawreviewras.tepserr");
open(ERRORSFOUND,">reviewras.tepserr");
while (<ERRORFILE>) {
s/^\s+$//;
print ERRORSFOUND "$_";
}
close(ERRORSFOUND);
close(ERRORFILE);

if (-z "reviewras.tepserr") {
	unlink("rawreviewras.tepserr");
	unlink("reviewras.tepserr");
} else {	
	open(ERRORFILE,"<reviewras.tepserr"); open(ERRORSFOUND,">$mostrctlog.reviewras.err");
	while (<ERRORFILE>) {
		s/^\s+$//;
		print ERRORSFOUND "$_\n";
	}
	close(ERRORSFOUND);
	close(ERRORFILE);
	close(TEPSERR);
	unlink("rawreviewras.tepserr");
	unlink("reviewras.tepserr");
	}

}

sub itm_errors {
my $searchcmsrunning=("Unable to find running CMS");

my @ARCms=grep(/$searchcmsrunning/,@ARLogarray) or my $cms=("none");
if ($#ARCms >= 0) {
	my $shiftcms=pop(@ARCms);
	chomp($shiftcms);
	$shiftcms=($shiftcms =~ /^(.)([\dA-F]+)(\..*)/);
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	print color 'bold';
	print "<<Solution:  Confirm Agent connect to TEMS by running 'tacmd listsystems' at HUB TEMS>>\n";
	print color 'reset';
}
}

sub tepsdbconnect_error {
my $tepsdbconnect=("unable to establish database connection to 'TEPS'");
my @ARTepsdbconnect=grep(/$tepsdbconnect/i,@ARLogarray) or my $tepsconnect=("none");
if ($#ARTepsdbconnect >= 0) {
	my $shifttepsdb=pop(@ARTepsdbconnect);
	chomp($shifttepsdb);
	if ($sLocalhostos eq "Windows") {
		$shifttepsdb=($shifttepsdb =~ /^(.)([\dA-F]+)(\..*)/);
		printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
		print "<<<Solution:  Confirm users can connect to TEPS database via command-line.>>>\n\n";
	} else {
	$shifttepsdb=($shifttepsdb =~ /^(.)([\dA-F]+)(\..*)/);
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	print color 'bold';
	print "<<<Solution:  Confirm users can connect to TEPS database via command-line.>>>\n\n";
	print color 'reset';
	}
}
}

sub check_bss1getenv {
my @ARBss1getenv1a=grep(/BSS1_GetEnv.*KFW_.*=.*CANDLE_HOME.*/,@ARLogarray);
if ($#ARBss1getenv1a < 0) {
	my $bss1getenv="No invalid TEPS environment variables found.\n";
} else {
	print "\nInvalid TEPS Environment Variables Found:\n";
	foreach my $bss1invalid (@ARBss1getenv1a) {
	my @ARBss1=split(/BSS1_GetEnv"\)\s/s,$bss1invalid);
	chomp (@ARBss1);
	print "$ARBss1[1]\n";
	}
	print color 'bold';
	print "<<<Solution:  Invalid Variables may cause the startup of the TEPS to fail. See technote:>>>\n";
  	print "http://www-01.ibm.com/support/docview.wss?uid=swg21391733\n";
	print color 'reset';
}
}

sub get_temsconnection {
my @ARTemsconnectionlist=grep(/\sKFW1011I\s\w+:\s|\sKFW1012I\s\w+:\s/i,@ARLogarray);
if ($#ARTemsconnectionlist >= 0) {
	
	foreach my $sRawTemsconnect(@ARTemsconnectionlist) {
		my ($sTemsconnect) = $sRawTemsconnect =~ m/I\s\w+:\s(.*?)$/;
		print "Connection Statement: $sTemsconnect\n";
	}
}
}

sub get_kfw1100i {
my @ARKfw1100ilist=grep(/\sKFW1100I\s\w+/i,@ARLogarray);
if ($#ARKfw1100ilist > 0) {
	my $sRawKfw1100i = pop(@ARKfw1100ilist) ;
	my ($sKfw1100i) = $sRawKfw1100i =~ m/client\scount:\s(.*?)$/;
	print "\nMost recent number of TEP clients connected(KFW1100I): $sKfw1100i\n";

}
}

sub get_tdwconnection {
my @ARFetchtdw=grep(/fetchWarehouse\"\)\s+?Warehouse\sfound\s/i,@ARLogarray);
chomp(@ARFetchtdw);
if ($#ARFetchtdw >= 0) {
	my $sFetch = pop(@ARFetchtdw);
	($sFetch) = $sFetch =~ m/fetchWarehouse\"\)\s+?(.*?)$/i;
	print "\n$sFetch\n";
}
my @ARTdwlist=grep(/describeDataSource\"\)\sDatasource|describeDataSource\"\)\s+DBMS\sName|describeDataSource\"\)\s+DBMS\sVersion/i,@ARLogarray);
chomp(@ARTdwlist);
if ($#ARTdwlist >= 0) {
	print "\nDatawarehouse Connection Information:\n";
	foreach my $sRawdbmsinfo(@ARTdwlist) {
	my ($sDbmsvalue) = $sRawdbmsinfo =~ m/describeDataSource\"\)\s+?(\w+.*?)$/;
	print "$sDbmsvalue\n";
	}
}
}

sub check_kfwmsenu {
my @ARKfwmsenu=grep(/Message Base open failed using/,@ARLogarray);
print "@ARKfwmsenu";
if ($#ARKfwmsenu >= 0) {
	print color 'bold';
	print "<<<Solution:  Check the KFW_MSG_BUNDLE variable in the TEPS env. file (Windows=kfwenv)>>>\n";
	print "The value must be defined with the fully qualified path to KFWMSENU\n";
	print "ex: KFW_MSG_BUNDLE=C:\\IBM\\ITM\\cnps\\KFWMSENU\n";	
	print color 'reset';
}
}

sub jdbcservice_message {
my @ARJdbcservice=grep(/KFW1\d{2}3I\sStarted\s\w+\W\s'JDBC/,@ARLogarray);
if ($#ARJdbcservice < 0) {
	if ($sLocalhostos eq "Windows") {
		print "\nDid not find \"JDBC Service Started message\".  If the JDBC service fails to start and the TEPS (ITM 6.2 or greater) is configured to connect to an Oracle data warehouse, the TEPS will be unable to connect to the data warehouse.\n\n";
	} else {
		print color 'bold';
		print "\nDid not find \"JDBC Service Started message\".  If the JDBC service fails to start and the TEPS (ITM 6.2 or greater) is configured to connect to an Oracle data warehouse, the TEPS will be unable to connect to the data warehouse.\n\n";
		print color 'reset';
	}
}
}

sub sql0443n_error {
my @ARsql0443n=grep(/SQL0443N/,@ARLogarray) or my $sql0443n=("none");
if ($#ARsql0443n >= 0) {
	my $shiftsql0443n=pop(@ARsql0443n);
	chomp($shiftsql0443n);
	$shiftsql0443n=($shiftsql0443n =~ /^(.)([\dA-F]+)(\..*)/);
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	if ($sLocalhostos eq "Windows") {
		print "<<Solution: DB2 bind must take place.\n";
		print "See ITM 6 documentation: http://publib.boulder.ibm.com/infocenter/tivihelp/v15r1/index.jsp?topic=/com.ibm.itm.doc/pdg_itm62234.htm\n";
	} else {
		print color 'bold';
		print "<<Solution: DB2 bind must take place.\n";
		print "See ITM 6 documentation: http://publib.boulder.ibm.com/infocenter/tivihelp/v15r1/index.jsp?topic=/com.ibm.itm.doc/pdg_itm62234.htm\n";
		print color 'reset';
	}
}
}

sub sql1032n_error {
my @ARsql1032n=grep(/SQL1032N/,@ARLogarray) or my $sql1032n=("none");
if ($#ARsql1032n >= 0) {
	my $shiftsql1032n=pop(@ARsql1032n);
	chomp($shiftsql1032n);
	$shiftsql1032n=($shiftsql1032n =~ /^(.)([\dA-F]+)(\..*)/);
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	if ($sLocalhostos eq "Windows") {
	print "<<Solution: Start the DB2 database manager using 'db2start'.>>\n";
	} else {
	print color 'bold';
	print "<<Solution: Start the DB2 database manager using 'db2start'.>>\n";
	print color 'reset';
	}
}
}

sub sql1224n_error {
my @ARsql1224n=grep(/SQL1224N/,@ARLogarray) or my $sql1224n=("none");
if ($#ARsql1224n >= 0) {
	my $shiftsql1224n=pop(@ARsql1224n);
	chomp($shiftsql1224n);
	$shiftsql1224n=($shiftsql1224n =~ /^(.)([\dA-F]+)(\..*)/);
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	if ($sLocalhostos eq "Windows") {
		print "<<Solution: Start the DB2 database manager using 'db2start'.>>\n";
	} else {
	print color 'bold';
	print "<<Solution: Start the DB2 database manager using 'db2start'.>>\n";
	print color 'reset';
	}
}
}

sub sql30082n_error {
my @ARsql30082n=grep(/SQL30082N/,@ARLogarray) or my $sqlerr30082n=("none");
if ($#ARsql30082n >= 0) {
	my $sSql30082n=pop(@ARsql30082n);
	chomp($sSql30082n);
	if ($sLocalhostos eq "Windows") {
	$sSql30082n=($sSql30082n =~ /^(.)([\dA-F]+)(\..*)/);
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	} else {
	$sSql30082n=($sSql30082n =~ /^(.)([\dA-F]+)(\..*)/);
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	print color 'bold';
	print "<<<Solution:  Confirm the username and password used to connect to the TEPS and Data Warehouse.>>>\n";
	print color 'reset';
	}
}
}

sub portshare_error {
my $searchportshare=("Port sharing unavailable");
my @ARPortshare=grep(/$searchportshare/,@ARLogarray) or my $port=("none");
if ($#ARPortshare >= 0) {
	my $shiftport=pop(@ARPortshare);
	chomp($shiftport);
	print "$shiftport\n";
	if ($sLocalhostos eq "Windows") {
		print "<<Solution: http://www-01.ibm.com/support/docview.wss?uid=swg21403349 >>\n";
	} else {	
		print color 'bold';
		print "<<Solution: http://www-01.ibm.com/support/docview.wss?uid=swg21403349 >>\n";
		print color 'reset';
	}
}
}

sub d102362_error {
my @ARD102362=grep(/Table not found <TOCONFIG>/i,@ARLogarray) or my $d102362=("none");
if ($#ARD102362 >= 0) {
	my $sD102362=pop(@ARD102362);
	chomp($sD102362);
	$sD102362=($sD102362 =~ /^(.)([\dA-F]+)(\..*)/);
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	if ($sLocalhostos eq "Windows") {
	print "<<<Solution:\nCreate SQL file (/tmp/toconfig.sql) with this text:\nDELETE FROM O4SRV.TSITDESC WHERE SITNAME = \"UADVISOR_KTO_TOCONFIG\"\;\nUse kdstsns to remove the entry\n# cd to the directory where sql file resides  (/tmp) \n# export SQLLIB=\$PWD   (When running kdstsns from Linux/UNIX server)                                         \n# Use kdstsns to run the toconfig.sql file kdstsns /tmp/toconfig.sql *HUB\n# Stop the TEPS and TEMS\n# Start the TEMS and TEPS\n";
print ">>>\n";
	} else {
	print color 'bold';
	print "<<<Solution:\nCreate SQL file (/tmp/toconfig.sql) with this text:\nDELETE FROM O4SRV.TSITDESC WHERE SITNAME = \"UADVISOR_KTO_TOCONFIG\"\;\nUse kdstsns to remove the entry\n# cd to the directory where sql file resides  (/tmp) \n# export SQLLIB=\$PWD   (When running kdstsns from Linux/UNIX server)                                         \n# Use kdstsns to run the toconfig.sql file kdstsns /tmp/toconfig.sql *HUB\n# Stop the TEPS and TEMS\n# Start the TEMS and TEPS\n";
	print color 'reset';
	}
}
}

# Subroutines for various DB2 Errors
sub db2_errors {
unlink("reviewras.db2err");
#my @ARDb2err=grep(/SQL(\d){4}[C-W]|SQL(\d){5}[C-W]/,@ARLogarray);
# Change below made 09-14-2016 David W.
my @ARDb2err=grep(/SQL(\d){4}[C\s|N\s|W\s]|SQL(\d){5}[C\s|N\s|W\s]/,@ARLogarray);
my $itotdb2err = $#ARDb2err +1;
if ($#ARDb2err >= 0) {
	open(DB2ERR,">reviewras.db2err");
	foreach my $sDB2error(@ARDb2err) {
	print DB2ERR "$sDB2error";
	}
	close(DB2ERR);
	
	open(ERRORFILE,"<reviewras.db2err");
	open(DBERRORFILE,">$mostrctlog.reviewras.db2err");
	while (<ERRORFILE>) {
		$_ =~ /^(.)([\dA-F]+)(\..*)/;
		printf DBERRORFILE "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}
	close(DBERRORFILE);
	close(ERRORFILE);
	unlink("reviewras.db2err");
	print color 'bold';
	print "\nDB2 Errors Found:\n";
	print "DB2 Database Errors stored in $mostrctlog.reviewras.db2err\n";
	print color 'reset';
	}
}

# Subroutines for various Oracle Errors
sub ora_errors {
my @AROraerr=grep(/ORA-(\d){5}/,@ARLogarray);
my $itotoraerr = $#AROraerr +1;
if ($#AROraerr >= 0) {
	open(ORAERR,">reviewras.oraerr");
	foreach my $sOraerror(@AROraerr) {
	print ORAERR "$sOraerror\n";
	}
	close(ORAERR);
	
	open(ERRORFILE,"<reviewras.oraerr");
	open(DBERRORFILE,">$mostrctlog.reviewras.oraerr");
	while (<ERRORFILE>) {
		s/^\s+$//;
		print DBERRORFILE "$_\n";
	}
	unlink("reviewras.oraerr");
	close(ERRORFILE);
	close(DBERRORFILE);
	print "\nOracle Errors Found: \n";
	print "Oracle Database Errors stored in $mostrctlog.reviewras.oraerr\n";
	} else {
	unlink("reviewras.oraerr");
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

sub err_corba_systemexception {
my @ARCorbalist=grep(/RAS_CORBA_\w+Exception/i,@ARLogarray);
if ($#ARCorbalist >= 0) {
	unlink("reviewras.corbaexceptions");
	open (INSERTS,">reviewras.corbaexceptions");
	foreach my $sCorbaexception(@ARCorbalist) {
		$sCorbaexception=($sCorbaexception =~ /^(.)([\dA-F]+)(\..*)/);
		printf INSERTS "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}
	close(INSERTS);
	open(INSERTFILE,"<reviewras.corbaexceptions");
	open(OUTPUTFILE,">$mostrctlog.reviewras.corbaexceptions");
	while(<INSERTFILE>) {
		s/^\s$//;
		print OUTPUTFILE "$_";
	}
	close("INSERTFILE");
	unlink("reviewras.corbaexceptions");
	close("OUTPUTFILE");
	if ($sLocalhostos eq "Windows") {
		print "\nRAS_CORBA_SystemException errors found in RAS log.\n";	
		print "Errors stored in $mostrctlog.reviewras.corbaexceptions\n";
	} else {
	print color 'bold';
		print "\nRAS_CORBA_SystemException errors found in RAS log.\n";	
		print "Errors stored in $mostrctlog.reviewras.corbaexceptions\n";
	print color 'reset';
	}
}
}

# Common ITM RAS Subroutines

sub get_compdriverlvl {
my @ARcomponentmatch= grep(/\s+?$searchitmcomponent/,@ARLogarray);
chomp(@ARcomponentmatch);
my @ARdrivermatch= grep(/.\.(\w){4}\s+?$searchitmdriver/,@ARLogarray);
chomp(@ARdrivermatch);
my $iloop=0;

if ($#ARcomponentmatch eq $#ARdrivermatch) {
	foreach (@ARcomponentmatch) {
		my ($sComponent) = $_ =~ m/\sComponent:\s(.*?)$/;
		my ($sDriver) = $ARdrivermatch[$iloop] =~ m/\sDriver:\s(.*?)$/;
		chomp($sDriver);
		if ($sLocalhostos eq "Windows") {
		print "$sComponent\tDriver: $sDriver\n";
		$iloop++;
		} else {
		if ($sComponent =~ m/kcj/) {
			print color 'bold green';
			print "$sComponent\tDriver: $sDriver\n";
			print color 'reset';
			$iloop++;
		} else {	
			print "$sComponent\tDriver: $sDriver\n";
			$iloop++;
		}
		}
	}
} else {
	print "Total number of Component IDs does not match total number of drivers levels.\n Review log to confirm component and driver level.\n";
}
}
	

sub get_EOF {
open (LOG,"<$mostrctlog");
my @ARLogarray =  <LOG>;
close(LOG);
my $sPoplogarray=$ARLogarray[$#ARLogarray];
my @AREof=grep(/^[\(|\+]/,$sPoplogarray);
	if ($#AREof < 0) {
		print "\n\t********** \tEnd of file reached\t **********\n";
		print "$sPoplogarray";
	}	
}

sub sda_warning {
my @ARSda=grep(/missing\sthe\sKFWAPPSUPPORT/i,@ARLogarray) or my $sSda=("none");
#	print "\nDEBUG>>>>> $#ARSda\n";
	if ($#ARSda >=0 ) {
		print "\nWARNING: KFWAPPSUPPORT Table is missing from TEPS database.  SDA updates to TEPS will fail without this table.\n";
	} else {
		$sSda=("none");
	}
}

sub  err_warehousesumprune {
my @ARWarehousesumprune=grep(/Error\sretrieving\sSumm|exception\scaught\sdetermining\scolumn\ssize\sfor\sWAREHOUSESUMPRUNE/,@ARLogarray);
if ($#ARWarehousesumprune >= 0) {
	my $sWarehousesumprune=pop(@ARWarehousesumprune);		
	chomp($sWarehousesumprune);
	print "\nError gathering data warehouse table information:\n$sWarehousesumprune\n";
	print "<<<<<<<<Solution: Check the TEPS configuration connection to the data warehouse.>>>>>>>>\n";
	
}
	else {
	print "\n";
	}
}

sub err_aix_IV77462 {
my @ARIV77462=grep(/Conversation\stimeout:.*1C010008/,@ARLogarray);
if ($#ARIV77462 >= 0) {
	my $sIV77462=pop(@ARIV77462);
	chomp($sIV77462);
	print "$sIV77462\n";
	print color 'bold';
	print "\nError found indicating APAR IV77462 is being encountered\n";
	print "See technote:  http://www-01.ibm.com/support/docview.wss?uid=swg21968342\n";
	print color 'reset';
		
}
}

sub mess_invalid_data {
my @ARDatamember=grep(/Exception:\sinvalid\sData\smember/,@ARLogarray);
if ($#ARDatamember >=50) {
		my $sDatamembers=pop(@ARDatamember);
		chomp($sDatamembers);
		print "Safe to ignore:\n$sDatamembers\n";
		print "See PMR: 53794,057,649\n"
}
}
