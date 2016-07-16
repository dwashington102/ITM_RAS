#!/usr/bin/perl 
# ewasreview.pl
# Script will parse SystemOut.log. Gathering useful information, locate known errors, and
# provide solutions for some known errors
#################################################################################
# Date: 2010/09/17
#
# Revision History:
# Revision 1.3.1 2010/10/22
#	changed $searchewasver from 'WebSphere Platform' to 'embeddedEXPRESS'
#
# Revision 1.3 2010/10/22
# 	corrected defect d-20101022a
#
# Revision 1.2 2010/10/06
#	added err_load_jdbc(), err_ctgtre042w(), err_wksp();
#	replaced err_cwwim2009e() and err_cwwim4520e() with err_cwwim
#	changed grep in @ARSecjauth to detect SECJ0305I messages
#
# Revision 1.1 2010/09/30
# 	changed $sDebugsetting to account for non-English SystemOut.log files
#	>	($sDebugsetting) = $sDebugsetting =~ m/\*=(.*?)$/;
#	from	($sDebugsetting) = $sDebugsetting =~ m/\strace\sstate\sis\s(.*?)$/;
#
# Revision 1.0 2010/09/17
# Author: David Washington
# washingd@us.ibm.com
#
#################################################################################
# Defects Found:
# 2010/10/22:
# d-20101022a - Use of uninitialized value $sKfwjvmctjdbc 
# Changed: ($sKfwjvmctjdbc) = $sKfwjvmctjdbc =~ m/\sclasspath:(.*?):\sclassName/;
# To: ($sKfwjvmctjdbc) = $sKfwjvmctjdbc =~ m/\sclasspath:(.*?)\sclassName:/;
#################################################################################

use strict;
use warnings;
use Term::ANSIColor;
use Cwd;

##################################################################################
#######################     Set Variables      ###################################
##################################################################################
my $currentdir=cwd;
my $iloop=0;

my $sOsplatform=undef;
my $sEwasver=undef;
my $sProcessid=undef;
my $sJavaver=undef;
my $sJavahome=undef;
my $sEwasinstall=undef;
my $sDebugsetting=undef;
my $sTepsdebug=undef; 
my $sLastaction=undef;
my $sNextaction=undef;
my $sCheckpassword=undef;
my $sDate=undef;
my $sDate_last=undef;
my $sDate_next=undef;
my $sInvaliduid=undef;
my $sCwwim2009euid=undef;
my $sCwwim2009e=undef;
my $sCwwim4520e=undef;
my $sCwwimcode=undef;
my $sCtgtre=undef;
my $sKfwjvmctjdbc=undef;
my $sEwasusername=undef;
my $sAwk_err=undef;
my $sTcrbuild=undef;
my $sSecjauth=undef;
my $sFailed=undef;
my $sLoadjdbc=undef;
my $sCtgtre042w=undef;
my $sReport=undef;
my $sMessage=undef;
my $sAdmn=undef;
my $sAdmncode=undef;
my $sWksp=undef;
my $sWkspcode=undef;

undef my @ARWksp;
undef my @ARAdmn;
undef my @ARCtgtre042w;
undef my @ARLoadjdbc;
undef my @ARFailed;
undef my @ARSecjauth;
undef my @ARTcrbuild;
undef my @ARAwk_err;
undef my @AREwasusername;
undef my @ARKfwjvmctjdbc;
undef my @ARCtgtre;
undef my @ARCwwim4520e;
undef my @ARCwwim2009e;
undef my @AROsplatform;
undef my @AREwasver;
undef my @ARPid;
undef my @ARJavaver;
undef my @ARJavahome;
undef my @AREwasinstall;
undef my @ARDebugsetting;
undef my @ARTepsdebug;
undef my @ARStartup;
undef my @ARShutdown;
undef my @ARActionlist;
undef my @ARCheckpassword;

##################################################################################
##################     Set Search String Variables ###############################
##################################################################################
my $searchosplatform=("Host Operating System is ");
my $searchewasver=("embeddedEXPRESS ");
#my $searchewasver=("WebSphere Platform ");
my $searchpid=(" process id ");
my $searchjavaver=("Java version ");
my $searchjavahome=("Java Home ");
my $searchewasinstall=("was.install.root ");

#################################################################################
#####################   Common Get LocalHost OS   ###############################
#################################################################################
my $sRawOS=$^O;
my $sLocalhostos=substr($sRawOS,0,5);

if ($sLocalhostos eq "MSWin") {
        $sLocalhostos=("Windows");
} else {
	$sLocalhostos=$sRawOS;
}

##################################################################################
#######################        Main Program    ###################################
##################################################################################
my $mostrctlog=$ARGV[0] or die "Usage: ewasreview.pl SystemOut.log\n\n";
check_filename();
open (LOG,"<$mostrctlog");
our @ARLogarray =  <LOG>;
close(LOG);

print "\n#######################################################\n";
print "\t$mostrctlog\n";
print "#######################################################\n";
print "Host OS, Java and eWAS Information:\n\n";
get_osplatform();
get_tcrbuild();
get_javaver();
get_javahome();
get_ewasver();
get_ewasinstall();
get_ewaspid();
get_kfwjvmctjdbc();
print "\n#######################################################\n";
print "\n#######################################################\n";
print "Debug Trace Settings:\n";
get_debug();
get_tepsdebug();
print "\n#######################################################\n";

print "#######################################################\n";
print "eWAS Startup/Shutdown Information:\n\n";
get_startup_shutdown();
print "\n#######################################################\n";

print "#######################################################\n";
print "Errors Found:\n\n";
err_load_jdbc();
err_secj_auth();
err_password();
err_cwwim();
#err_cwwim2009e();
#err_cwwim4520e();
err_ctgrte();
err_admn();
err_awk();
err_execute();
err_wksp();
print "\n#######################################################\n";

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
} else {
	print "Unable to process $mostrctlog.\n";	
}
}

sub get_osplatform  {
@AROsplatform=grep(/^$searchosplatform/i,@ARLogarray) or print "Host Operating System NOT FOUND.\n";
chomp(@AROsplatform);
if ($#AROsplatform >= 0) {
	($sOsplatform)=shift(@AROsplatform);	
	if ($sOsplatform =~ m/Linux/) {
		($sOsplatform) =~ s/, version/: Kernel version /;
		print "$sOsplatform\n";
	} else {
		print "$sOsplatform\n";
	}
}
}

sub get_javaver {
@ARJavaver=grep(/^$searchjavaver/i,@ARLogarray) or print "Java Version NOT FOUND.\n";
chomp(@ARJavaver);
if ($#ARJavaver >= 0) {
	$sJavaver=shift(@ARJavaver);	
	print "$sJavaver\n";
}
}

sub get_javahome {
@ARJavahome=grep(/^$searchjavahome/i,@ARLogarray) or print "Java HOME NOT FOUND.\n";
chomp(@ARJavahome);
if ($#ARJavahome >= 0) {
	$sJavahome=shift(@ARJavahome);	
	print "$sJavahome\n";
}
}

sub get_ewasver {
@AREwasver=grep(/$searchewasver/i,@ARLogarray) or print "eWAS Version NOT FOUND.\n";
chomp(@AREwasver);
if ($#AREwasver >= 0) {
	$sEwasver=pop(@AREwasver);	
	($sEwasver) = $sEwasver =~ m/^(.*?)\]\s+?/;
	print "eWAS Version: $sEwasver]\n";
}
}

sub get_ewasinstall {
@AREwasinstall=grep(/^$searchewasinstall/i,@ARLogarray) or print "eWAS Install directory NOT FOUND.\n";
chomp(@AREwasinstall);
if ($#AREwasinstall >= 0) {
	$sEwasinstall=pop(@AREwasinstall);	
	($sEwasinstall) = $sEwasinstall =~ m/=\s(.*?)$/;
	print "eWAS Install Directory: $sEwasinstall\n";
}
}

sub get_ewaspid {
@ARPid=grep(/$searchpid/i,@ARLogarray) or print "eWAS PID NOT FOUND.\n";
chomp(@ARPid);
if ($#ARPid >= 0) {
	$sProcessid=pop(@ARPid);
	($sProcessid) = $sProcessid =~ m/\sand\s(.*?)$/;
	get_userid();
	print "eWAS $sProcessid\n";
}
}

sub get_userid {
@AREwasusername=grep(/\suser.name\s=/i,@ARLogarray);
chomp(@AREwasusername);
if ($#AREwasusername >= 0) {
	$sEwasusername=pop(@AREwasusername);
	($sEwasusername) = $sEwasusername =~ m/\s=\s(.*?)$/;
	print "ewas started using username $sEwasusername\n";
}
}

sub get_debug {
@ARDebugsetting=grep(/TRAS001[7-8]I/i,@ARLogarray) or print "\nDebug setting NOT FOUND.\n";
chomp(@ARDebugsetting);
if ($#ARDebugsetting >= 0) {
	$sDebugsetting=pop(@ARDebugsetting);
	($sDate) = $sDebugsetting =~ m/^\[(.*?)\]\s/;
	($sDebugsetting) = $sDebugsetting =~ m/\*=(.*?)$/;
	print "\neWAS Trace level:\tSet at [$sDate] \*=$sDebugsetting\n";
}
}

sub get_tepsdebug {
@ARTepsdebug=grep(/New Filter: /i,@ARLogarray);
chomp(@ARTepsdebug);
if ($#ARTepsdebug >= 0) {
	$sTepsdebug=pop(@ARTepsdebug);
	($sDate) = $sTepsdebug =~ m/^\[(.*?)\]\s/;
	($sTepsdebug) = $sTepsdebug =~ m/\sNew\sFilter:\s(.*?)$/;
	print "\nTEPS Trace level:\t$sTepsdebug\nSet at [$sDate]\n";
}
}

sub get_kfwjvmctjdbc {
@ARKfwjvmctjdbc=grep(/KFW_JVM__CTJDBC\sclasspath:/i,@ARLogarray);
chomp(@ARKfwjvmctjdbc);
if ($#ARKfwjvmctjdbc >= 0) {
	$sKfwjvmctjdbc=pop(@ARKfwjvmctjdbc);
	($sKfwjvmctjdbc) = $sKfwjvmctjdbc =~ m/\sclasspath:(.*?)\sclassName:/;
	print "\nKFW_JVM__CTJDBC: $sKfwjvmctjdbc\n";
}
}

sub get_tcrbuild {
@ARTcrbuild=grep(/\sWSVR0203I:\sApplication:\stcr/i,@ARLogarray);
chomp(@ARTcrbuild);
if ($#ARTcrbuild >=0) {
	$sTcrbuild=pop(@ARTcrbuild);
	($sTcrbuild) = $sTcrbuild =~ m/\sbuild\slevel:\s(.*?)$/;
	print "\nTCR Build Level: $sTcrbuild\n\n";
}
}

##################################################################################
#######################   Start/Shutdown Subroutines   ###########################
##################################################################################

sub get_startup_shutdown {
# WSVR0001I = eWAS startup
# WSVR0024I = eWAS shutdown
@ARActionlist=grep(/WSVR0001I|WSVR0024I/i,@ARLogarray);
if ($#ARActionlist >= 0) {
	chomp(@ARActionlist);
	$sLastaction=pop(@ARActionlist);
	($sDate_last) = $sLastaction =~ m/^\[(.*?)\]\s/;
	if ($sLastaction =~ m/WSVR0024I/) {
		$sNextaction=pop(@ARActionlist);
		($sDate_next) = $sNextaction =~ m/^\[(.*?)\]\s/;
		if ($sNextaction =~ m/WSVR0001I/) {
		($sNextaction) = $sNextaction =~ m/WSVR(.*?)$/i;
		($sLastaction) = $sLastaction =~ m/WSVR(.*?)$/i;
		print "Most recent eWAS Startup Message:\n[$sDate_next] WSVR$sNextaction\n";
		print "\neWAS Shutdown Message appears after most recent eWAS startup message:\n[$sDate_last] WSVR$sLastaction\n";
		print "\nConfirm eWAS is currently running.\n";
		} else {
		($sLastaction) = $sLastaction =~ m/WSVR(.*?)$/i;
		print "Most recent eWAS Shutdown Message:\n[$sDate_last] WSVR$sLastaction\n";
		print "Review SystemOut.log for WSVR0001I messages to confirm the date/time for the most recent eWAS startup.\n";
		}
	} else {
	($sLastaction) = $sLastaction =~ m/WSVR(.*?)$/i;
	print "Most recent eWAS Startup Message:\n[$sDate_last] WSVR$sLastaction\n";
	}
}
}

##################################################################################
#######################   Error Subroutines    ###################################
##################################################################################
sub err_password {
@ARCheckpassword=grep(/Invalid\suserid\s/i,@ARLogarray);
chomp(@ARCheckpassword);
if ($#ARCheckpassword >= 0) {
	if ($sLocalhostos eq "Windows") {
		print "\nInvalid Username/Password Errors:\n";
	} else {
		print color 'bold';
		print "\nInvalid Username/Password Errors:\n";
		print color 'reset';
	}
	foreach $sCheckpassword(@ARCheckpassword) {
		($sDate) = $sCheckpassword =~ m/^\[(.*?)\]\s/;
		($sInvaliduid) = $sCheckpassword =~ m/Invalid\suserid\s(.*?)$/;
		print "[$sDate]\tInvalid userid $sInvaliduid\n";
	}
}
}

sub err_cwwim {
# Used to only read lines that begin with [ DATE ]
my @ARDatelogarray=grep(/^\[/,@ARLogarray);
@ARCwwim2009e=grep(/\sCWWIM(\d){4}E/i,@ARDatelogarray);
chomp(@ARCwwim2009e);
if ($#ARCwwim2009e >= 0) {
	if ($sLocalhostos eq "Windows") {
		print "\nCWWIM Message errors found:\n";
	} else {
		print color 'bold';
		print "\nCWWIM Message errors found:\n";
		print color 'reset';
	}
	foreach $sCwwim2009e(@ARCwwim2009e) {
		($sDate) = $sCwwim2009e =~ m/^\[(.*?)\]\s/;
		($sCwwimcode) = $sCwwim2009e =~ m/\sCW(.*?)E\s/;
		($sMessage) = $sCwwim2009e =~ m/$sCwwimcode\w(.*?)$/;
		print "[$sDate] CW"."$sCwwimcode"."E $sMessage\n";
	}
	print "\n";
}
}

#sub err_cwwim2009e {
#@ARCwwim2009e=grep(/\s CWWIM2009E\sThe\sprincipal\s/i,@ARLogarray);
#chomp(@ARCwwim2009e);
#if ($#ARCwwim2009e >= 0) {
#	if ($sLocalhostos eq "Windows") {
#		print "\nCWWIM2009E errors found:\n";
#	} else {
#		print color 'bold';
#		print "\nCWWIM2009E errors found:\n";
#		print color 'reset';
#	}
#	foreach $sCwwim2009e(@ARCwwim2009e) {
#		($sDate) = $sCwwim2009e =~ m/^\[(.*?)\]\s/;
#		($sCwwim2009euid) = $sCwwim2009e =~ m/AccessException\s(.*?)$/;
#		print "[$sDate] $sCwwim2009euid\n";
#	}
#	print "\n";
#}
#}

sub err_cwwim4520e {
@ARCwwim4520e=grep(/\.ldapadapter\s\w+\sCWWIM4520E\sThe\s/i,@ARLogarray);
chomp(@ARCwwim4520e);
if ($#ARCwwim4520e >= 0) {
	if ($sLocalhostos eq "Windows") {
		print "\nCWWIM4520E errors found:\n";
	} else {
		print color 'bold';
		print "\nCWWIM4520E errors found:\n";
		print color 'reset';
	}
	foreach $sCwwim4520e(@ARCwwim4520e) {
		($sDate) = $sCwwim4520e =~ m/^\[(.*?)\]\s/;
		($sCwwim4520e) = $sCwwim4520e =~ m/\s??CWWIM(.*?)$/;
		print "[$sDate] CWWIM".$sCwwim4520e,"\n";
	}
	print "\n";
}
}

sub err_ctgrte {
@ARCtgtre=grep(/\sCTGTR[A-Z](\d){3}E/,@ARLogarray);
chomp(@ARCtgtre);
if ($#ARCtgtre >= 0) {
	if ($sLocalhostos eq "Windows") {
		print "\nCTGTR errors found:\n";
	} else {
		print color 'bold';
		print "\nCTGTR errors found:\n";
		print color 'reset';
	}
	foreach $sCtgtre(@ARCtgtre) {
		($sDate) = $sCtgtre =~ m/^\[(.*?)\]\s/;
		($sCtgtre) = $sCtgtre =~ m/\s??CTGTR(.*?)$/;
		print "[$sDate] CTGTR".$sCtgtre,"\n";
	}
	print "\n";
}
}

sub err_admn {
@ARAdmn=grep(/\sA[C-D](\w){2}(\d){4}E/,@ARLogarray);
chomp(@ARAdmn); 
if ($#ARAdmn >= 0) {
	if ($sLocalhostos eq "Windows") {
		print "\nApplication Server error messages found:\n";
	} else {
		print color 'bold';
		print "\nApplication Server error messages found:\n";
		print color 'reset';
	}
	foreach $sAdmn(@ARAdmn) {
	if ($sAdmn =~ m/^\[(.*?)\]\s/) {
		($sDate) = $sAdmn =~ m/^\[(.*?)\]\s/;
		($sAdmncode)= $sAdmn =~ m/\sA(.*?)E/;
		($sMessage) = $sAdmn =~ m/$sAdmncode\w(.*?)$/;
		print "[$sDate]: A".$sAdmncode."E"," $sMessage\n";
	} else {
		print "$sAdmn\n";
	}
	}
}
}

sub err_wksp {
@ARWksp=grep(/\sWKSP(\d){4}E/,@ARLogarray);
chomp(@ARWksp); 
if ($#ARWksp >= 0) {
	if ($sLocalhostos eq "Windows") {
		print "\nWKSP Application Server error messages found:\n";
	} else {
		print color 'bold';
		print "\nWKSP Application Server error messages found:\n";
		print "Error codes defined at URL:\n http://publib.boulder.ibm.com/infocenter/wasinfo/fep/index.jsp?topic=/com.ibm.websphere.messages.doc/com.ibm.ws.management.resources.configservice.html\n\n";		
		print color 'reset';
	}
	foreach $sWksp(@ARWksp) {
	($sDate) = $sWksp =~ m/^\[(.*?)\]\s/;
	($sWkspcode)= $sWksp =~ m/\sWKSP(.*?)E/;
	($sMessage) = $sWksp =~ m/$sWkspcode\w(.*?)$/;
	print "[$sDate]: WKSP".$sWkspcode."E"," $sMessage\n";
	}
}
}


sub err_awk {
@ARAwk_err=grep(/\sAWK(\w){3}(\d){3}E/,@ARLogarray);
chomp(@ARAwk_err); 
if ($#ARAwk_err >= 0) {
	if ($sLocalhostos eq "Windows") {
		print "\nUtility error messages found:\n";
	} else {
		print color 'bold';
		print "\nUtility errors messages found:\n";
		print color 'reset';
	}
	foreach $sAwk_err(@ARAwk_err) {
	($sDate) = $sAwk_err =~ m/^\[(.*?)\]\s/;
	($sAwk_err) = $sAwk_err =~ m/\s??AWK(.*?)$/;
	print "[$sDate] AWK".$sAwk_err,"\n";
	}
}
}

sub err_secj_auth {
@ARSecjauth=grep(/SECJ01(\d+){2}E|SECJ0305I/,@ARLogarray);
#@ARSecjauth=grep(/SECJ01(\d+){2}E/,@ARLogarray);
chomp(@ARSecjauth);
if ($#ARSecjauth >= 0) {
	if ($sLocalhostos eq "Windows") {
		print "\nUser authorization error messages found:\n";
	} else {
		print color 'bold';
		print "\nUser authorization errors messages found:\n";
		print color 'reset';
	}
	foreach $sSecjauth(@ARSecjauth) {
	($sDate) = $sSecjauth =~ m/^\[(.*?)\]\s/;
	($sSecjauth) = $sSecjauth =~ m/\s??SECJ(.*?)$/;
	print "[$sDate] SECJ".$sSecjauth,"\n";
	}	
}
}

sub err_execute {
@ARFailed=grep(/failed to execute\s/i,@ARLogarray);
chomp(@ARFailed);
if ($#ARFailed >= 0) {
	if ($sLocalhostos eq "Windows") {
		print "\nFailed to Execute error messages found:\n";
	} else {
		print color 'bold';
		print "\nFailed to Execute error messages found:\n";
		print color 'reset';
	}
	foreach $sFailed(@ARFailed) {
	($sDate) = $sFailed =~ m/^\[(.*?)\]\s/;
	print "$sFailed\n";
	}
}
}

sub err_load_jdbc {
@ARLoadjdbc=grep(/Cannot load JDBC Driver class/i,@ARLogarray);
chomp(@ARLoadjdbc);
@ARCtgtre042w=grep(/CTGTRE042W/,@ARLogarray);
chomp(@ARCtgtre042w);
if ($#ARLoadjdbc >= 0) {
	if ($sLocalhostos eq "Windows") {
		print "\nFailed to load JDBC Driver messages found:\n";
	} else {
		print color 'bold';
		print "\nFailed to load JDBC Driver messages found:\n";
		print color 'reset';
	}		
	foreach $sLoadjdbc(@ARLoadjdbc) {
	($sDate) = $ARCtgtre042w[$iloop] =~ m/^\[(.*?)\]\s/;
	($sReport) = $ARCtgtre042w[$iloop] =~ m/\s\[\s\/(.*?)\]\s\w/;
	print "[$sDate] $sLoadjdbc Report Name: ( $sReport)\n";
	$iloop++;
	}
} else {
	err_ctgtre042w();
}
}

sub err_ctgtre042w {
if ($#ARCtgtre042w >= 0) { 
	if ($sLocalhostos eq "Windows") {
		print "\nLoading report WARNING messages found:\n";
	} else {
		print color 'bold';
		print "\nLoading report WARNING messages found:\n";
		print color 'reset';
	}		
	foreach $sCtgtre042w(@ARCtgtre042w) {
	($sDate) = $sCtgtre042w =~ m/^\[(.*?)\]\s/;
	($sMessage) = $sCtgtre042w =~ m/s\s\[(.*?)$/;
	if ($sCtgtre042w =~ m/\[\snull\s\]\s/) {
		$sReport="null ";
	} else {
		($sReport) = $sCtgtre042w =~ m/\s\[\s\/(.*?)\]\s\w/;
	}
	print "[$sDate] CTGTRE042W REPORT NAME: ( $sReport) MESSAGE: [ $sMessage ]\n";
	}
}
}

#sub err_tdw_url {
#@ARTdwerr=grep(/Invalid database url/i,@ARLogarray);
#chomp(@ARTdwerr);
#if ($#ARTdwerr >= 0) {
#	if ($sLocalhostos eq "Windows") {
#		print "\nDatabase URL syntax error messages found:\n";
#	} else {
#		print color 'bold';
#		print "\nDatabase URL syntax error messages found:\n";
#		print color 'reset';
#	}
#	foreach $sTdwerr(@ARTdwerr) {
#		print "$sTdwerr\n";
#	}
#}
#}
