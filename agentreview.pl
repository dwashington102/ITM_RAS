#!/usr/bin/perl
# agentreview.pl
#------------------------------------------------------------------------------
# Licensed Materials - Property of IBM (C) Copyright IBM Corp. 2010, 2010
# All Rights Reserved US Government Users Restricted Rights - Use, duplication
# or disclosure restricted by GSA ADP Schedule Contract with IBM Corp
#------------------------------------------------------------------------------
# Script is AS-IS and not supported by IBM Support.
#------------------------------------------------------------------------------
# Script will parse ITM RAS logs. Gathering useful information, locate known errors, and
# provide solutions for known errors
# Author:David Washington
#################################################################################
# Date: 2010/08/21
#
# Revision History:
# Revision 2.0.3 2016/03/04
#	Added search to detect dynamic trace setting change "KBBRA_ChangeLogging"
# Revision 2.0.2 2015/06/08
# 	Added search for " failed, status = 66"
# Revision 2.0.1 2013/12/13
# 		Added search for add_listener
# Revision 2.0 2013/07/30
#	Added search for CANDLEHOME
# Revision 1.9 2013/04/26
#	Added search for "Process ID"
#
# Revision 1.8.1
#	Corrected defect d-20120829a
#
# Revision 1.8 2012/08/19
#	Added search for Nofiles Descriptor Setting
#
# Revision 1.7.1 2011/02/13
#	Changed \s+source/; to include = 
#	($sIpaddrsplt) = $sIpaddrstr =~ m/.\w\s+(.*?):\s+source=/;

# Revision 1.7 2011/0127
#	Corrected defect d-20110127a
#
# Revision 1.6  2010/10/24
#	added @ARDb2agent checking for DB2 agent RAS log and calling db2_errors when found
#	changed @itmmatchtype to print Linux " - Kernel Version"
#
# Revision 1.5.1 2010/10/7
# 	Corrected defect d-20101007a
#
# Revision 1.5 2010/10/1
#	changed get_EOF() replaced 
#	> my @AREof=grep(/^\(/,$sPoplogarray);
#
# Revision 1.4 2010/09/26:
#	changed get_EOF() to get last element of @ARLogarray rather than pop @ARLogarray
# 	corrected $ARExportline foreach { else { if "Windows"
# 		> after changing hextime to wall time code incorrectly attempted
#		>print "$ARExportline\n";
#	
# Revision 1.3 2010/09/15:
#	added check_filename() - confirms file passed is valid
#
# Revision 1.2 2010/09/13:
#	get_EOF() - Added to detect and display EOF
#	get_cms_connectdate() - Added to print date/time agent connects to TEMS
#	added 0 byte size checking (-z $mostrctlog)
#	added access permission checking (!-r $mostrctlog)
#
# Revision 1.1 2010/09/02:
# 		@itmmatchusername - Change to capture User Name when it appears as
#		+4C77DD8B.0000        User Name: SYSTEM     	System Type:....
#		rather than 
#		+4C0E460F.0000     Program Name: kntcma  	User Name: SYSTEM
#		Both instances are correctly captured with this change:
#		my ($sUsername) = $shiftmatchusername=~ m/User Name:\s+(.*?)\s/;
#
#		$sSysType, $sStartdate, $sStartTime - Change to use =~ /m 
#
# Revision 1.0 2010/02/01					
#################################################################################
# Defects Found:
# d-20120829a - @ARSwitchtems - Use of uninitialized value $ARcmssplit[1]
# Caused by "Primary TEMS" when text in RAS log shows
# "IRA_SetConnectWaitInterval") *INFO: Primary TEMS Fallback Switch Lookup Interval is 4500

# d-20110127a - @ARCms=0 would not correct display error found
# Changes:
# 	if ($#ARCms > 0) to if ($#ARCms >= 0)

# d-20101007a - Use of uninitialized value $ARKdebintersplit[1] 
# Caused by $searchkdebinterface searching for KDEB_INTERFACELIST rather than
# KDEB_INTERFACELIST=
#
#
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

# Searches used to extract network, TEMS, warehouse information.
my $searchitmipaddr=("source=");
my $searchkdc=("=KDC_FAMILIES=");
my $searchagentport=("KDEBP_AssignPort");
my $searchhttpkdhsqlqm=("kdhslqm.*add_listener.*listening");
my $searchctirahostname=("CTIRA_HOSTNAME");
my $searchkdebinterface=(" KDEB_INTERFACELIST=");
my $searchitmcms0=("CT_CMSLIST");
my $searchitmcms1=("Successfully connected to CMS");
my $searchwpa=("Setting new warehouse location");

# Common errors found in RAS logs 
my $searchcmsrunning=("Unable to find running CMS");

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
my $sKdhslqm=undef;
undef my @ARctirahost;
undef my @ARWpaconfig;
undef my @ARDb2agent;

#################################################################################
#####################      Get LocalHost OS      ################################
#################################################################################
my $sRawOS=$^O;
#print "Debug Value Raw: $sRawOS\n";
my $sLocalhostos=substr($sRawOS,0,5);

if ($sLocalhostos eq "MSWin") {
        $sLocalhostos=("Windows");
#        print "Operating System: $sLocalhostos\n";
} else {
	$sLocalhostos=$sRawOS;
#        print "Operating System: $sLocalhostos\n";
}
#################################################################################

##################################################################################
#######################        Main Program    ###################################
##################################################################################
my $mostrctlog=$ARGV[0] or die "Usage: agentreview.pl [RAS LOG]\n\n";
check_filename();

##################################################################################
# Allows script to run against RAS logs other than the RAS1 log 
my $RAS = rindex($mostrctlog, '1.log');
##################################################################################

open (LOG,"<$mostrctlog");
my @ARLogarray =  <LOG>;
close(LOG);

####################################################################
# Checks RAS1 logs 
####################################################################
if  ($RAS >=0) {
print "\n#######################################################\n";
print "\t\t$mostrctlog\n";
print "#######################################################\n";

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
}
else {
	my $shiftmatchsystem = shift(@itmmatchsystem);
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
	my $shiftmatchtype = shift(@itmmatchtype);
	my ($sSysType) = $shiftmatchtype =~ m/Type:\s+(.*?)\s/;
	if ($sSysType =~ m/Linux/) {
		($sSysType) =~ s/;/ - Kernel Version: /;
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
	my $shiftmatchdate = shift(@itmmatchdate);
	my ($sStartdate) = $shiftmatchdate =~ m/Date:\s+(.*?)\s/;
	print "Start Date: $sStartdate\n";
}

my @itmmatchtime = grep(/\d+\s+$searchitmstarttime/, @ARLogarray) or print "Start Time:\t";
if ($#itmmatchtime < 0) {
	print " NOT FOUND\n";
}
else {
	my $shiftmatchtime = shift(@itmmatchtime);
	my ($sStartTime) = $shiftmatchtime =~ m/Time:\s+(.*?)\s/; 
	print "Start Time: $sStartTime\n";
}

my @itmmatchusername=grep(/$searchusername/,@ARLogarray) or my $sUsernamenull=("NOT FOUND");
if ($#itmmatchusername < 0) {
	$sUsernamenull=("NOT FOUND");
} else {
	my $shiftmatchusername=shift(@itmmatchusername);
	my ($sUsername) = $shiftmatchusername=~ m/User Name:\s+(.*?)\s/;
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


my @ARkdcfamilies = grep (/$searchkdc/,@ARLogarray) or print "\nKDC_Families and Port Assignment:\t";
if ($#ARkdcfamilies < 0) {
	print "\nKDC_FAMILIES NOT FOUND\n";
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
		my @ARagentport=split(/KDEBP_AssignPort"\)/,$sPortassign);
		chomp (@ARagentport);
		print "$ARagentport[1]\n";
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
}
else {
	my $sShiftctirahostname=shift(@ARctirahostname);	
	@ARctirahost=split(/CTIRA_HOSTNAME=/,$sShiftctirahostname);
	chomp(@ARctirahost);
	print "\nCTIRA_HOSTNAME set to $ARctirahost[1]\n";
}

my @ARWpa=grep(/$searchwpa/i,@ARLogarray) or print "\nAgent's WPA configuration ";
if ($#ARWpa < 0) {
	print " NOT FOUND.\n NOTE: If debug UNIT kra is not enabled, the RAS log will not contain any warehouse register information.\n";
}
else {
	my $sShiftwpa=shift(@ARWpa);
	$sShiftwpa =~ s/\;/\n/g;
	@ARWpaconfig=split(/Address\"\)/,$sShiftwpa);
	chomp(@ARWpaconfig);
	print "\nAgent configured to connect to WPA using:\n $ARWpaconfig[1]\n";
	get_ctirahistdir();
}

my @itmcmsfound=grep(/$searchitmcms0|$searchitmcms1/,@ARLogarray) or print "\nAgent's configuration to TEMS";
if ($#itmcmsfound < 0) {
	print " NOT FOUND.\n";
}
else {
	my $sShiftcmsfound=shift(@itmcmsfound);
	my @ARcmssplit=split(/CT_CMSLIST=/,$sShiftcmsfound);
	chomp(@ARcmssplit);

my @ARSwitchtems=grep(/\)\sPrimary\sTEMS\s set\s to\s\</i,@ARLogarray);
if ($#ARSwitchtems >= 0 ) {
	print "\nAgent configured to connect to CMS (TEMS): $ARcmssplit[1]\n";
	get_cms_connectdate();
	print "Agent switched to secondary TEMS on these dates:\n";		
	cms_primary();
} else {
	print "\nAgent configured to connect to TEMS: $ARcmssplit[1]\n";
	get_cms_connectdate();
} 
}


print "\n#######################################################\n";
print "\n#######################################################\n";
print "Internal Components and Driver Levels:\n";
get_compdriverlvl();
print "\nTo match driver levels to ITM 6 versions, see URL:\nhttp://www-01.ibm.com/support/docview.wss?uid=swg27008514\n";
print "#######################################################\n";

print "\n#######################################################\n";
print "Errors Messages Found in RAS LOG:\n";
itm_errors();
export_fail66();
@ARDb2agent=grep(/kuddb2/i,$mostrctlog);
if ($#ARDb2agent >= 0) {
	db2_errors();
}

print "\n#######################################################\n";

my @ARExportcheck=grep(/\"routeExportRequest\"\)\sExport\s\w+(.*?)\sobject\s/i,@ARLogarray);
if ($#ARExportcheck >=0) {
print "\n#######################################################\n";
print "Export of historical data:\n";
tdw_exports();
print "\n#######################################################\n";
} 

print "\n#######################################################\n";
#Used to convert timestamps within RAS logs
convert_hextime();

####################################################################
# Checks RAS logs other than the RAS1 log
####################################################################
} else {
print "\n#######################################################\n";
print "\t\t$mostrctlog\n";
print "#######################################################\n";
cms_primary();
print "\n#######################################################\n";
print "Errors Messages Found in RAS LOG:\n";
itm_errors();
print "\n#######################################################\n";

my @ARExportcheck=grep(/\"routeExportRequest\"\)\sExport\s\w+(.*?)\sobject\s/i,@ARLogarray);
if ($#ARExportcheck >=0) {
print "\n#######################################################\n";
print "Export of historical data:\n";
tdw_exports();
print "\n#######################################################\n";
} 
print "\n#######################################################\n";

#Used to convert timestamps within RAS logs
convert_hextime();
}
get_EOF();
exit(0);

##################################################################################
#######################       Subroutines      ###################################
##################################################################################
sub export_fail66{
my $searchfail66=("failed, status = 66");
my @ARFail66=grep(/$searchfail66/,@ARLogarray) or my $fail66=("none");
	if ($#ARFail66 >= 0 ) {
		my $shiftfail66=pop(@ARFail66);
		chomp($shiftfail66);
		printf "\n$shiftfail66\n";
		printf "Status = 66 indicates a problem with khdexp.cfg\n";
		printf ">>>>>>>>>> Solution: http://www-01.ibm.com/support/docview.wss?uid=swg21426816\n";
	} else {
		my $fail66=("none");
		}
}

sub db2_errors {
unlink("reviewras.db2err");
my @ARDb2err=grep(/SQL(\d){4}[I-W]/,@ARLogarray);
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


sub itm_errors {
my $searchcmsrunning=("Unable to find running CMS");
my @ARCms=grep(/$searchcmsrunning/,@ARLogarray) or my $cms=("none");
if ($#ARCms >= 0) {
	my $shiftcms=pop(@ARCms);
	chomp($shiftcms);
	if ($sLocalhostos eq "Windows") {
	$shiftcms=($shiftcms =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	print "<<Solution:  Confirm Agent connect to TEMS by running 'tacmd listsystems' at HUB TEMS>>\n";
	} else {
	$shiftcms=($shiftcms =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	print color 'bold';
	print "<<Solution:  Confirm Agent connect to TEMS by running 'tacmd listsystems' at HUB TEMS>>\n";
	print color 'reset';
	}
} 
}

sub tdw_exports {
my $searchitmdebug=("KBB_RAS1:");
my @ARExports=grep(/\"routeExportRequest\"\)\sExport\s\w+(.*?)\sobject\s/i,@ARLogarray);
if ($#ARExports < 0) {
	my @itmmatchdebug = grep(/$searchitmdebug/, @ARLogarray) or print "\nKBB_RAS1 setting not found in $mostrctlog.\n";
	if ($#itmmatchdebug < 0 ) {
	print "Confirm KBB_RAS1 setting.\n";
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
} elsif ($#ARExports > 10) {
		my $poptdwinserts=pop(@ARExports);
		$poptdwinserts=($poptdwinserts =~ /^(.)([\dA-F]+)(\..*)/); 
		printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
		open(DBINSERTS,">reviewras.dbexports");
		foreach my $ARExportline(@ARExports) {
		$ARExportline=($ARExportline =~ /^(.)([\dA-F]+)(\..*)/); 
		printf DBINSERTS "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
		}
	 	close(DBINSERTS);
		open(INSERTFILE,"<reviewras.dbexports");	
		open(DBINSERTFILE,">$mostrctlog.reviewras.dbexports");
		while (<INSERTFILE>) {
		s/^\s$//;
		print DBINSERTFILE "$_";
		}
		unlink("reviewras.dbexports");
		close("INSERTFILE");
		close("DBINSERTFILE");	
		print "\nMore than 10 data exports found in RAS log.\n";
		print "Data exports stored in $mostrctlog.reviewras.dbexports\n";
} else {
	foreach my $ARExportline(@ARExports) {
		if ($ARExportline =~ /successful\.$/) {
			$ARExportline=($ARExportline =~ /^(.)([\dA-F]+)(\..*)/); 
			printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
		} else {
			if ($sLocalhostos eq "Windows") {
			$ARExportline=($ARExportline =~ /^(.)([\dA-F]+)(\..*)/); 
			printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
			} else {
			print color 'bold';
			$ARExportline=($ARExportline =~ /^(.)([\dA-F]+)(\..*)/); 
			printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
			print color 'reset';
			}
		}
	}
}
}

sub cms_primary {
my $searchitmdebug=("KBB_RAS1:");
my @ARPrimarycms=grep(/\)\sPrimary\sTEMS\s\</i,@ARLogarray);
if ($#ARPrimarycms >= 0) {
	foreach my $switchtems(@ARPrimarycms) {
		$switchtems=($switchtems =~ /^(.)([\dA-F]+)(\..*)/); 
		printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}
} 
}

sub convert_hextime {
print "Do you want to convert HEX timestamps in $mostrctlog (type \"yes\" or \"no\"):  \t";
my $sCONVERT=<STDIN>;
chomp($sCONVERT);
if (($sCONVERT eq "yes")||($sCONVERT eq "YES")) {
	system ("convertras.pl $mostrctlog");
	print "\nConverted ITM RAS log: $mostrctlog.reviewras.converted.\n";
}
print "\n#######################################################\n";
print "Review of $mostrctlog completed.\n\n";
}

sub get_cms_connectdate {
my @ARCmssuccess=grep(/connected\sto\sCMS/i,@ARLogarray) or return;
if ($#ARCmssuccess >=0 ) {
	my $popcmssuccess=pop(@ARCmssuccess);
	chomp($popcmssuccess);
	chomp(@ARCmssuccess);
	my @ARCmssuccess=split(/Successfully/,$popcmssuccess);
	my ($sCmssuccesstime)=$ARCmssuccess[1];
	chomp($sCmssuccesstime);
	print "$sCmssuccesstime\n Date of last successful connection to Primary TEMS:\t";
	my $sConvertcmssuccess=($popcmssuccess =~ /^(.)([\dA-F]+)(\..*)/); 
	printf "%s%s)\n", $1, scalar(localtime(oct("0x$2")));
} 
}

sub get_ctirahistdir {
my @ARHistdir=grep(/CTIRA_HIST_DIR/,@ARLogarray) or return;
if ($#ARHistdir >= 0) {
	my $popARHistdir=pop(@ARHistdir);
	my @splithistdir=split(/CTIRA_HIST_DIR="/,$popARHistdir);
	my $sCtirahistdir=pop(@splithistdir);
	$sCtirahistdir =~ s/"//g;
	print "\nCTIRA_HIST_DIR=$sCtirahistdir";
}
}

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
		if ($sComponent =~ m/knt|klz|kt6|kud|kul|kum|kux/) {
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

sub get_EOF {
open (LOG,"<$mostrctlog");
my @ARLogarray =  <LOG>;
close(LOG);
my $sPoplogarray=$ARLogarray[$#ARLogarray];
my @AREof=grep(/^[\(|\+]/,$sPoplogarray);
#my @AREof=grep(/^\(/,$sPoplogarray);
	if ($#AREof < 0) {
		print "\n\t********** \tEnd of file reached\t **********\n";
		print "$sPoplogarray"
	}	
}

