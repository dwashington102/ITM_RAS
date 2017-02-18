#!/usr/bin/perl
# temsreview.pl
# Date: 2010/08/21
#------------------------------------------------------------------------------
# Licensed Materials - Property of IBM (C) Copyright IBM Corp. 2010, 2010
# All Rights Reserved US Government Users Restricted Rights - Use, duplication
# or disclosure restricted by GSA ADP Schedule Contract with IBM Corp
#------------------------------------------------------------------------------
# Script is AS-IS and not supported by IBM Support.
#------------------------------------------------------------------------------
#
# Script will parse RAS1 log for the TEMS, gather useful information, and provide
# solutions for some known errors.
# Author David Washington
# washingd@us.ibm.com
#################################################################################
#
# Revision History:
# Revision 1.25 2016/11/22
# 	Added search kms_omtec() to detect "(5812A575.000E-1:kbbssge.c,72,"BSS1_GetEnv") KMS_OMTEC_INTEGRATION="XX""
# Revision 1.24 2016/08/19
# 	Added search kdhs_unsupported() to detect "Unsupported request method" messages that can be caused by NESSUS port scans
# Revision 1.23 2016/08/04
##       Added searh err_gmm() to detect "GMM1_AllocateStorage failed" errors
# Revision 1.22 2016/07/13
# 	Added search err_rrn to detect major/critical errors with the QA1CSTSH table/index at the TEMS
# Revision 1.21 2016/07/11
# 	Added search err_kfainvalid to detect invalid node name resulting in Agent failing to appear in listsystems output
# Revision 1.20 2016/03/04
#	Added search to detect dynamic trace setting change "KBBRA_ChangeLogging"
# Revision 1.19 2015/11/16
# 	Added search for "Filter object too big" to identify situations that can cause 
# 	performance issues (see PMR 90731,082,000) using err_sitfilter().
# 	Added search for SDA information.  KMS_SDA
# Revision 1.18 2015/11/09
#	Added search for KDEB_INTERFACELIST
# Revision 1.17 2015/07/27
# 	Added search for "CMS_FTO="
# Revision 1.16 2015/07/08
# 	Added search for "CTIRA_Recursive_lock objects"
# Revision 1.15 2015/06/29
# 	Added search for "Process ID"
#
# Revision 1.14 2014/11/14
# 		Added search for "Found warehouse GLB" and get_glb_warehouse()
# 
# Revision 1.9 2013/12/13
# 		Added search for add_listen
# Revision 1.8 2013/09/19
#	TO DO: Add VDM1_Malloc 
#
# Revision 1.7 2013/07/30
#	Added search for CANDLEHOME
# Revision 1.6 2010/10/24:
#	changed @itmmatchtype to print Linux Kernel version
#
# Revision 1.5 2010/09/24:
#	changed $sKdshub to use match rather than splitting an array
#	changed $sKdsrun to use match rather than splitting an array
#	changed $sSecurity to use match rather than splitting an array
# 	corrected $ARExportline foreach { else { if "Windows"
# 		> after changing hextime to wall time code incorrectly attempted
#		>print "$ARExportline\n";
#
# Revision 1.4 2010/09/15:
#	added check_filename() - confirms file passed is valid
#
# Revision 1.3 2010/09/14:
#	added 0 byte size checking (-z $mostrctlog)
#	added access permission checking (!-r $mostrctlog)
#	Removed opening @ARLogarray from all subroutines 
#		open (LOG,"<$mostrctlog");
#		my @ARLogarray =  <LOG>;
#		close(LOG);
#
# Revision 1.2  2010/09/06
# Changed search for Warehouse Registration ($searchwpa).
# Added @ARnodeid to capture TEMS name
# Added $popARExports to print most recent data export when @ARExports > 10
#
# Changed 	print "\nTEMS configured to export to WPA using:\n $ARWpaconfig[1]\n";
# to 	 	print "\nTEMS configured to export to WPA using:\n $ARWpaconfig[2]\n";
#
# Changed 	my @ARTsitdesclist=grep(/ProcessTable\sTSITDESC\sInsert\sError/i,@ARLogarray);
# to 		my @ARTsitdesclist=grep(/ProcessTable\s\w+\sInsert\sError/i,@ARLogarray);
#
# Revision History:
# Revision 1.1  2010/08/21
# Added search for Warehouse Registration ($searchwpa).
#
# Revision 1.0 2010/02/01					
#################################################################################

use strict;
use warnings;
use Cwd;
use Term::ANSIColor;

##################################################################################
#######################     Set Variables      ###################################
##################################################################################

my $currentdir = cwd;
my $iforloop =0;
my $iforloopnic =1;

# Specific searches for TEMS logs
my $searchulimit=("Nofile Limit: ");
my $searchkdsrun=("KDS_RUN=\"");
my $searchomtec=("KMS_OMTEC_INTEGRATION=\"");
my $searchkdshub=("KDS_HUB=\"");
my $searchnodeid=(" CMS_NODEID=\"");
my $searchkdsvalidate=("KDS_VALIDATE=\"");
my $searchcmsvalidate=("CMS_VALIDATE=\"");
my $searchctiralock=("CTIRA_Recursive_lock objects");
my $searchfto=("CMS_FTO=\"");
my $searchsda=("KMS_SDA=\"");

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
my $searchwpa=("CheckWarehouseReg");
my $searchpid=(" Process ID: ");
my $searchcandlehome=(" CANDLEHOME=\"");
my $searchkdebinterface=(" KDEB_INTERFACELIST=");

# Searches used to extract network information.
my $searchitmipaddr=("source=");
my $searchkdc=("=KDC_FAMILIES=");
my $searchagentport=("KDEBP_AssignPort");
my $searchhttpkdhsqlqm=("kdhslqm.*add_listener.*listening");
# undefined variables
my $sHost=undef;
my $sStarttime=undef;
my $sIpaddrsplt=undef;
my $scomponentmatch=undef;
my $itotdb2err=undef;
my $sHextime=undef;
my $sSysType=undef;
my $sStartTime=undef;
my $sPortassign=undef;
my $sKdhslqm=undef;
undef my @ARctirahost;

# Error Variables
my $err_kfa_invalidname=undef;
my $err_rrn=undef;
my $sErr_gmm=undef;


#################################################################################
# Get LocalHost OS                                                              #
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
# Main Program 
##################################################################################
my $mostrctlog=$ARGV[0] or die "Usage: temsreview.pl [RAS LOG]\n\n";
check_filename();

print "\n#######################################################\n";
print "\t\t$mostrctlog\n";
print "#######################################################\n";

open (LOG,"<$mostrctlog");
my @ARLogarray =  <LOG>;
close(LOG);

my @itmmatchdebug = grep(/$searchitmdebug/,@ARLogarray) or print "KBB_RAS1 setting not found.\n";
if ($#itmmatchdebug < 0 ) {
	print "Confirm KBB_RAS1 setting is enabled.\n";
}
else {
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
	$_=shift(@itmmatchtype);
	($sSysType) = $_ =~ m/System\sType:\s(.*?)\s+?/;
	if ($sSysType =~ m/Linux/) {
		($sSysType) =~ s/;/- Kernel Version: /;
		print "System Type: $sSysType\n";
	} else {
		print "System Type: $sSysType\n";
	}
}
	#my $shiftmatchtype = shift(@itmmatchtype);
	#my @systemtype=split(/System Type:/,$shiftmatchtype);
	#chomp(@systemtype);
	#$sSysType=substr($systemtype[1],0,10);
	#print "System Type: $sSysType\n";

my @itmmatchdate = grep(/$searchitmstartdate/, @ARLogarray) or print "Start Date:\t";
if ($#itmmatchdate < 0) {
	print " NOT FOUND\n";
}
else {
	my $shiftmatchdate = shift(@itmmatchdate);
	my @startdate=split(/Start Date:/,$shiftmatchdate);
	chomp(@startdate);
	my $sStartdate=substr($startdate[1],0,12);
	print "Start Date: $sStartdate\n";
}

my @itmmatchtime = grep(/\d+\s+$searchitmstarttime/, @ARLogarray) or print "Start Time:\t";
if ($#itmmatchtime < 0) {
	print " NOT FOUND\n";
}
else {
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

my @ARulimit=grep(/$searchulimit/,@ARLogarray) or print "\nNofile Limit setting ";
if ($#ARulimit < 0) {
	print " NOT FOUND\n";
}
else {
	my $shiftmatchulimit=shift(@ARulimit);
	my @ulimitinfo=split(/KBB_RAS1:/,$shiftmatchulimit);
	my $sString="@ulimitinfo";
	my ($sUlimit) = $sString =~ m/Nofile\sLimit:\s(.*?)\s+/;
	print "Nofile Limit setting: $sUlimit\n";
}



print "#######################################################\n";
print "\n#######################################################\n";
print "Network Information:\n";
my @ARipaddrmatch = grep (/\.\d+:\s$searchitmipaddr/,@ARLogarray) or print "\nIP address:\t";
if ($#ARipaddrmatch < 0) {
	print " NOT FOUND\n";		
} else {
	foreach	my $sIpaddrstr (@ARipaddrmatch) {
	($sIpaddrsplt) = $sIpaddrstr =~ m/.\w\s+(.*?):\s+source/;
	print "Network Interface Card[$iforloopnic]: $sIpaddrsplt\n";
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


my @ARkdcfamilies = grep (/$searchkdc/,@ARLogarray) or print "\nKDC_Families and Port Assignment:\n";
if ($#ARkdcfamilies < 0) {
	print "KDC_FAMILIES setting NOT FOUND\n";
}
else {
	my $sKdcstr="@ARkdcfamilies";
	my @ARkdcf=split(/KDC_FAMILIES="/,$sKdcstr);
	chomp(@ARkdcf);
	print "\nKDC_FAMILIES setting:\n$ARkdcf[1]\n";
}

my @ARPortassign=grep(/$searchagentport\"\)\s\w(.*?)\sbound\sto\sport\s/, @ARLogarray) or print "\nPort Assignment ";
if ($#ARPortassign < 0) {
	print " NOT FOUND\n";
}
else {
	print "\nPort Agent is connected to:\n";
	foreach $sPortassign (@ARPortassign) {
		my @ARagentport=split(/KDEBP_AssignPort"\)\s/,$sPortassign);
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

############# Specific to TEMS RAS logs ########################
my @ARNodeid=grep(/$searchnodeid/,@ARLogarray) or print "\nCMS_NODEID setting ";
if ($#ARNodeid < 0) {
	print " NOT FOUND\n";
} else {
	my $shiftmatchnode=shift(@ARNodeid);
	my ($sNodeid) = $shiftmatchnode =~ m/CMS_NODEID=\"(.*?)\"/;
	print "\nTEMS name (CMS_NODEID): $sNodeid\n";
}


my @ARkdshub=grep(/$searchkdshub/,@ARLogarray) or print "KDS_HUB setting ";
if ($#ARkdshub < 0) {
	print " NOT FOUND\n";
} else {
	my $shiftmatchhub=shift(@ARkdshub);
	#my @kdshub=split(/KDS_HUB=/,$shiftmatchhub);
	#chomp(@kdshub);
	#my $sKdshub=($kdshub[1]);
	#$sKdshub=~s/"//g;
	my ($sKdshub) = $shiftmatchhub =~ m/KDS_HUB=\"(.*?)\"/;
	if ($sKdshub eq "*LOCAL") {
		print "\nTEMS Type (KDS_HUB): HUB TEMS\n";
	} else {
		print "\nTEMS Type (KDS_HUB): Remote TEMS\n";
	}
}	

my @ARkdsrun=grep(/$searchkdsrun/,@ARLogarray) or print "KDS_RUN setting ";
if ($#ARkdsrun < 0) {
	print " NOT FOUND\n";
}
else {
	my $shiftmatchrun=shift(@ARkdsrun);
	my ($sKdsrun) = $shiftmatchrun =~ m/KDS_RUN=\"(.*?)\"/;
	print "\nKDS_RUN setting: $sKdsrun\n";
}

my @ARomtec=grep(/$searchomtec/,@ARLogarray) or print "\nKMS_OMTEC_INTEGRATION setting for EIF EVENTS: ";
if ($#ARomtec < 0) {
	print " NOT FOUND\n";
}
else {
	my $shiftmatchomtec=shift(@ARomtec);
	my ($sKdsomtec) = $shiftmatchomtec =~ m/KMS_OMTEC_INTEGRATION=\"(.*?)\"/;
	print "\nKDS_OMTEC_INTEGRATION setting for EIF EVENTS: $sKdsomtec\n";
}


my @ARkdsvalidate=grep(/[CMS|KDS]_VALIDATE/,@ARLogarray) or print "Security settings(KDS_VALIDATE) ";
if ($#ARkdsvalidate < 0) {
	print " NOT FOUND\n"
}
else {
	my $shiftmatchvalidate=shift(@ARkdsvalidate);
	my ($sSecurity) = $shiftmatchvalidate =~ m/_VALIDATE=\"(.*?)\"/;
	print "\nSecurity Settings(KDS_VALIDATE) set to:  $sSecurity\n";
}

my @ARfto=grep(/$searchfto/,@ARLogarray) or print "\nFailover setting CMS_FTO =  ";
if ($#ARfto < 0) {
	print " NOT FOUND\n"
}
else {
	my $shiftmatchfto=shift(@ARfto);
	my ($sFto) = $shiftmatchfto =~ m/CMS_FTO=\"(.*?)\"/;
	print "\nFailover setting(CMS_FTO)=$sFto\n";
}

my @ARSda=grep(/$searchsda/,@ARLogarray) or print "\nSDA setting KMS_SDA =  ";
if ($#ARSda < 0) {
	print " NOT FOUND\n"
}
else {
	my $shiftmatchsda=shift(@ARSda);
	my ($sSda) = $shiftmatchsda =~ m/KMS_SDA=\"(.*?)\"/;
	print "\nSDA setting(KMS_SDA) = $sSda\n";
}


my @ARctiralock=grep(/$searchctiralock/,@ARLogarray) or print "\nMAX_CTIRA_RECURSIVE_LOCKS setting:  ";
if ($#ARctiralock < 0) {
	print " NOT FOUND\n"
}
else {
	my $shiftmatchcitralock=shift(@ARctiralock);
	my ($sLock) = $shiftmatchcitralock =~ m/Using\s(.*)/;
	print "\nMAX_CTIRA_RECURSIVE_LOCKS (must be 150+):  $sLock\n";
}

my @ARWpa=grep(/$searchwpa\"\)\sWarehouse\sregistration/i,@ARLogarray) or print "\nTEMS WPA configuration ";
if ($#ARWpa < 0) {
	print " NOT FOUND.\n NOTE: If debug UNIT kpxrwhpx is not enabled, the RAS log will not contain any warehouse register information.\n";
}
else {
	my $sShiftwpa=shift(@ARWpa);
	$sShiftwpa =~ s/\;/\n/g;
	my @ARWpaconfig=split(/location\s\<(.*?)/,$sShiftwpa);
	chomp(@ARWpaconfig);
	if ($#ARWpaconfig >= 0) {
		print "\nTEMS configured to export to WPA using:\n $ARWpaconfig[2]\n";
	} else {
		my $popARWpaconfig=pop(@ARWpaconfig);
		print "TEMS configured to export to WPA using:\n$popARWpaconfig\n";
	}
}

get_glb_warehouse();

print "\n#######################################################\n";

print "\n#######################################################\n";
print "Internal Components and Driver Levels:\n";
get_compdriverlvl();
print "\nComponent kds is TEMS\n";
print "\nTo match driver levels to ITM 6 versions, see URL:\nhttp://www-01.ibm.com/support/docview.wss?uid=swg27008514\n";
print "#######################################################\n";

print "\n#######################################################\n";
print "ERROR Messages Found in RAS LOG:\n";
err_tsitdesc();
err_sitfilter();
err_kfainvalid();
err_rrn();
err_gmm();
kdhs_unsupported();

print "\n#######################################################\n";

my @ARExportcheck=grep(/\"routeExportRequest\"\)\sExport\s\w+(.*?)\sobject\s/i,@ARLogarray);
if ($#ARExportcheck >=0) {
print "\n#######################################################\n";
print "Export of historical data:\n";
tdw_exports();
print "\n#######################################################\n";
} else {
	my $sExportcheck=("none");
}

#Used to convert timestamps within RAS logs
print "\n#######################################################\n";
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
#######################        Subroutines     ###################################
##################################################################################
sub kdhs_unsupported{
# Used to extract text from the RAS log
my @ARKdhs_un=grep(/\sUnsupported\srequest\smethod\s\"/,@ARLogarray) or my $sErr_kdhs=("none");

# If the value of the array is < 0, exit function
if ($#ARKdhs_un < 0 ) {
#	printf "DEBUG --- in IF statement\n";
	return(0);

# If the value of the array is > 10, write messages to a log rather than dumping to console
} elsif ($#ARKdhs_un > 10) {
	printf "\nMore than 10 Unsupported Request Method Messages found.\n";
	open(INSERTFILE,">reviewras.kdhs");
	foreach my $ARKdhsline(@ARKdhs_un) {
		printf INSERTFILE "$ARKdhsline";	
		}
	close(INSERTFILE);
	open(ERRORFILE,"<reviewras.kdhs");
	open(KDHSUN,">$mostrctlog.reviewras.kdhs_unsupported");
	while (<ERRORFILE>) {
		print KDHSUN "$_\n";	
		}
	unlink("reviewras.kdhs");
	close(ERRORFILE);
	close(KDHSUN);
	print "Unsupported Request Messages written to $mostrctlog.reviewras.kdhs_unsupported\n";

# If the value of the array is > 0, but < 10 write messages to console 
} else {
	foreach my $ARKdhsline(@ARKdhs_un) {
		printf "Debug: $ARKdhsline\n";
	}
	}
}

sub err_gmm {
my @ARGmm=grep(/\sGMM1_AllocateStorage\sfailed\s/,@ARLogarray) or my $sErr_gmm=("none");
	if ($#ARGmm <=0) {
		$sErr_gmm="0";
} else {
	print "ERROR:  GMM1_AllocateStorage Failures found.\n";
	print "Review TEMS configuration file for the variables\t";
	print "KDS_HEAP_SIZE and KGL_GMMSTORE\n";
	print color 'bold';
	print "Set both variables to 2048.";
	print color 'reset';
}
}
	
		
sub err_rrn {
my @ARRrn=grep(/ERROR:\sfor\sRRN/,@ARLogarray) or my $err_rrn=("none");
	if ($#ARRrn <= 0) {
		$err_rrn="0";
	} else {
	print "\nERROR: Problems found in QA1 files.\n"	;
	print "Search $mostrctlog for the text \"RRN\"\n\n";
	}

}

sub err_kfainvalid {
my @ARKfainvalid=grep(/KFA_InvalidNameMessage/,@ARLogarray) or my $err_kfa_invalidname=("none");
	if ($#ARKfainvalid <= 0 ) {
		$err_kfa_invalidname="0";
	} 
	else {
	print "\nERROR:  Invalid Node Names found within log.\n";
	print "Search $mostrctlog for the text \"Validation for node failed\"\n";
	}
}

sub get_glb_warehouse {
my @ARGlbwarehouse=grep(/Found\swarehouse\sGLB\saddress\sof\s/,@ARLogarray) or my $sGlbwarehouse=("none");
print "\nRegistered Warehouse Hosts:";
	if ($#ARGlbwarehouse >=0 ){
	foreach $sGlbwarehouse(@ARGlbwarehouse) {
		my @ARFoundglb=split(/Found\s/s,$sGlbwarehouse);
		chomp (@ARFoundglb);
		print "\nFound $ARFoundglb[1]\n";
	}
	} else {
		print "--------------No GLB Warehouse Registration Information Found-------------";
	}
}

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

sub err_tsitdesc {
my @ARTsitdesclist=grep(/ProcessTable\s\w+\sInsert\sError/i,@ARLogarray);
#my @ARTsitdesclist=grep(/ProcessTable\sTSITDESC\sInsert\sError/i,@ARLogarray);
if ($#ARTsitdesclist >= 0) {
	open(TSITDESC,">reviewras.tsitdesc");
	foreach my $ARTsitdescline(@ARTsitdesclist) {
		$ARTsitdescline=($ARTsitdescline =~ /^(.)([\dA-F]+)(\..*)/); 
		printf TSITDESC "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
	}
	close(TSITDESC);
	open(INSERTFILE,"<reviewras.tsitdesc");
	open(OUTPUTFILE,">$mostrctlog.reviewras.tsitdesc");
	while (<INSERTFILE>) {
		s/^\s$//;
		print OUTPUTFILE "$_";
	}
	unlink("reviewras.tsitdesc");
	close("INSERTFILE");
	close("OUTPUTFILE");
print "Errors to TEMS tables found in log.  Errors stored  in $mostrctlog.reviewras.tsitdesc\n";  
}
}

sub err_sitfilter{
undef my $ARFiltersit=undef;
# Used to extract text from the RAS log
my @ARFiltersit=grep(/Filter\sobject\stoo\sbig\s/i,@ARLogarray);

# If the value of the array is < 0, exit function
if ($#ARFiltersit <0) { 
	return(0);
#
# If the value of the array is > 10, write messages to a log rather than dumping to console
} elsif ($#ARFiltersit > 10) {
	printf "\nMore than 10 \"Filter object too big\" messages found.\n";
	open(INSERTFILE,">reviewras.filter");
	foreach my $ARFilterfound(@ARFiltersit) {
		printf INSERTFILE "$ARFilterfound";
	}
	close(INSERTFILE);
	open(ERRORFILE,"<reviewras.filter");
	open(FILTER,">$mostrctlog.reviewras.filter_too_big");
	while(<ERRORFILE>) {
		print FILTER "$_\n";
	}
	unlink("reviewras.filter");
	close(ERRORFILE);
	close(FILTER);
	printf "Filter object too big messages written to $mostrctlog.reviewras.filter_too_big\n";

# If the value of the array is <0, but >10 write messages to console 
} else {
	print "\nSituation Filter Issues:\n";
	foreach $ARFiltersit(@ARFiltersit) {
		print "$ARFiltersit";
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
	return(0);
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
		open(DBINSERTS,">reviewras.dbexports");
		my $popARExports=pop(@ARExports);
		$popARExports=($popARExports =~ /^(.)([\dA-F]+)(\..*)/); 
		printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
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
		print "More than 10 data exports found in RAS log.\n";
		print "Data exports stored in $mostrctlog.reviewras.dbexports\n";
} else {
	foreach my $ARExportline(@ARExports) {
		if ($ARExportline =~ /successful\.$/) {
			$ARExportline=($ARExportline =~ /^(.)([\dA-F]+)(\..*)/); 
			printf "%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3;
		} else {
			if ($sLocalhostos eq "Windows") {
			$ARExportline=($ARExportline =~ /^(.)([\dA-F]+)(\..*)/); 
			print "$ARExportline\n";
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
		if ($ARcompsplit[1] eq "kds") {
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
