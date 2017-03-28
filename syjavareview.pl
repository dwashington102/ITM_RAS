#!/usr/bin/perl
# syjavareview.pl
# Date: 2010/08/21
#------------------------------------------------------------------------------
# Licensed Materials - Property of IBM (C) Copyright IBM Corp. 2010, 2010
# All Rights Reserved US Government Users Restricted Rights - Use, duplication
# or disclosure restricted by GSA ADP Schedule Contract with IBM Corp
#------------------------------------------------------------------------------
# Script is AS-IS and not supported by IBM Support.
#------------------------------------------------------------------------------
# Script will parse SY Java logs gathering useful information
# and identify common errors found in the log.
# Author: David Washington
# washingd@us.ibm.com
#################################################################################
#										
# Revision History:
#
# Revision 1.4 2016/05/05:
# Changed line:
# print "\n<<<  Solution:  Locate tables causing SQLException using: grep -E "^== 2012|t=work<x> $mostrctlog | grep -i -E \"Examining|SQLException|Memory in bytes\"  >>>\n";
# to
# print "\n<<<  Solution:  Locate tables causing SQLException using: grep -E \"^== 2012|t=work<x>\" $mostrctlog | grep -i -E \"Examining|SQLException|Exception|Memory in bytes\"  >>>\n";
# 
# Revision 1.3.1 2012/08/16:
# 	> Changed text printed to line
#	 print "\n<<<  Solution:  Locate tables causing SQLException using: grep t=work{x} $mostrctlog | grep -i -E \"Examining|SQLException\"  >>>\n";
#	to
#	 print "\n<<<  Solution:  Locate tables causing SQLException using: grep -E "^== 2012|t=work<x> $mostrctlog | grep -i -E \"Examining|SQLException|Memory in bytes\"  >>>\n";
#
# Revision 1.3 2012/05/06:
#	> added err_sqlexception() to isolate tables being aggregated/pruned when
# 	SQLException is throw
# 	> changed get_histconfig() adding an OR (|)  
# 	> Moved text "Tables that take more than..." into the else statement in order
# 	to avoid the line being printed every time script is ran
#
# Revision 1.2 2010/09/15:
#	added check_filename() - confirms logfile is valid
#
# Revision 1.1 2010/09/14:
#	added 0 byte size checking (-z $mostrctlog)
#	added access permission checking (!-r $mostrctlog)
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
my $searchmajorver=(" majorVersion");
my $searchminorver=(" minorVersion");
my $searchmaintenancever=(" maintenanceVersion");
my $searchfixver=(" fixVersion");
my $searchcnp=("CNP server host");
my $searchcnpport=("CNP server port");
my $searchmaxworkers=("maxWorkers ");
my $searchmaxrows=("maxRowsPerTransaction");
my $searchwarehousejars=("warehouseJars");
my $searchscheduled=("nextWorkTime");
my $successicount=0;
my $searchTDWURL = ("Attempting connection with URL ");
# Undefined Variables
my $sSytable=undef;
my $userlongrunning=undef;
my $sURL=undef;
undef my @ARVersion;
undef my @ARLongrunning;

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
my $mostrctlog=$ARGV[0] or die "Usage: syjavareview.pl [SY JAVA LOG]\n\n";
check_filename();

$userlongrunning=("600");
# Used to allow user input, when looking for tables that take more than X seconds to process
#print "Number of seconds for max. time: \t";
#$userlongrunning=<STDIN>;
#if ($userlongrunning !~ /^\d+$/) {
#	print "Please insert a valid number of seconds. Only numeric characters.\n";
#	exit(1);
#} elsif ($userlongrunning < 1||$userlongrunning > 86400) {
#	print "Please insert a valid number of seconds (1 - 86400).\n";
#	exit(1);
#} else {
#	chomp($userlongrunning);
#}

##################################################################################
# Allows script to run against RAS logs other than the RAS1 log 
my $RAS = rindex($mostrctlog, '1.log');
##################################################################################

open (LOG,"<$mostrctlog");
my @ARLogarray =  <LOG>;
close(LOG);

# SY Java Version Information
my @matchmajorver=grep(/$searchmajorver/i,@ARLogarray) or my $majorver=("Version NOT FOUND");
chomp(@matchmajorver);

my @matchminorver=grep(/$searchminorver/i,@ARLogarray) or my $minorver=("Version NOT FOUND");
chomp(@matchminorver);

my @matchmaintver=grep(/$searchmaintenancever/i,@ARLogarray) or my $maintver=("Version NOT FOUND");
chomp(@matchmaintver);

my @matchfixver=grep(/$searchfixver/i,@ARLogarray) or my $fixver=("Version NOT FOUND");
chomp(@matchfixver);


##################################################################################
# When running syjavareview.pl against RAS logs (2-5+), if information that's usually written to RAS1
# appears in the log file, the @ARCheckcfg will set the $RAS value to causing syjavareview.pl to treat
# RAS log as a RAS1 log.
##################################################################################
print "Beginning review of log...\n";
my @ARCheckcfg=grep(/$searchmajorver||$searchminorver||$searchmaintenancever||$searchfixver/i,@ARLogarray) or $RAS="-1";
if ($#ARCheckcfg >=0) {
	$RAS="0";
}

if  ($RAS >=0) {
print "\n#######################################################\n";
print "\t\t$mostrctlog\n";
print "#######################################################\n";

print "\n#######################################################\n";
if ($#matchmajorver < 0) {
	print "Unable to locate SY Agent version level.\n";
} else {
	my $shiftmajorver=shift(@matchmajorver);
	($shiftmajorver) =~ s/\x0D//g;
	my @ARMajorver=split(/\s:\s/,$shiftmajorver);
	
	my $shiftminorver=shift(@matchminorver);
	($shiftminorver) =~  s/\x0D//g;
	my  @ARMinorver=split(/\s:\s/,$shiftminorver);
	
	my $shiftmaintver=shift(@matchmaintver);
	($shiftmaintver) =~ s/\x0D//g;
	my @ARMaintver=split(/\s:\s/,$shiftmaintver);
	
	my $shiftfixver=shift(@matchfixver);
	($shiftfixver) =~ s/\x0D//g;
	my @ARFixver=split(/\s:\s/,$shiftfixver);
	
	print "SY Agent Code Level and TEPS configuration:\n\n";
	print "SY Agent is running at code level:\n$ARMajorver[1].$ARMinorver[1].$ARMaintver[1].$ARFixver[1]\n";
}

##################################################################################
#Scheduled Run Time for SY agent
##################################################################################
my @matchscheduled = grep(/$searchscheduled/i, @ARLogarray) or print "Scheduled start time NOT FOUND.\n";
if ($#matchscheduled < 0 ) {
	print "Confirm start time for SY.\n";
} else {
	my $shiftscheduled1=pop(@matchscheduled);
	my @ARSplitscheduled1=split(/MSc=\d+/,$shiftscheduled1);
	chomp(@ARSplitscheduled1);
	my $sRuntime=shift(@ARSplitscheduled1);
	my @ARRuntime=split(/nextWorkTime\s+:\s/i,$sRuntime);
	chomp(@ARRuntime);
	print "\nSY Agent will next run at:\n @ARRuntime\n";   
}

##################################################################################
# SY agent configuration connection to TEPS
##################################################################################
my @matchcnp=grep(/$searchcnp/i,@ARLogarray) or print "TEPS hostname ";
if ($#matchcnp < 0) {
	print "NOT FOUND.\n";
} else {
	my $shiftcnp=shift(@matchcnp);
	($shiftcnp) =~ s/\x0D//g;
	my @ARSplitcnp=split(/\s:\s/,$shiftcnp);
	chomp(@ARSplitcnp);
	my ($sCnphost)=substr($ARSplitcnp[1],0,35);
	print "\nSY is configured to connect to TEPS HOSTNAME (CNP server host):\n\t$sCnphost";
	print "\n";
}

my @matchcnpport=grep(/$searchcnpport/i,@ARLogarray) or print "TEPS port number ";
if ($#matchcnpport < 0) {
	print "NOT FOUND.\n";
} else {
	my $shiftcnpport=shift(@matchcnpport);
	($shiftcnpport) =~ s/\x0D//g;
	my @ARSplitcnpport=split(/\s:\s/,$shiftcnpport);
	chomp(@ARSplitcnpport);
	my $sCnpport=substr($ARSplitcnpport[1],0,15);
	print "\tTEPS Port Number: $sCnpport\n";
}

##################################################################################
# SY agent Configuration Information
##################################################################################
print "\n#######################################################\n";
print "SY Database and Configuration Information:\n\n";

my @matchURL=grep(/$searchTDWURL/,@ARLogarray) or print "Warehouse URL ";
if ($#matchURL < 0) {
	print "NOT FOUND.\n";
} else {
	my $shiftURL=pop(@matchURL);
	($shiftURL) =~ s/\x0D//g;
	my @ARsplitURL=split(/\sURL\s:\s/,$shiftURL);
	chomp(@ARsplitURL);
	my $sURLraw="$ARsplitURL[1]";
	($sURL) = $sURLraw =~ m/\((.*?)\)\suser/;
	print "Warehouse URL: $sURL\n";
}
	
my @matchschema=grep(/warehouseSchema/,@ARLogarray) or print "Warehouse Schema ";
if ($#matchschema < 0) {
	print "NOT FOUND.\n";
} else {
	my $shiftschema=pop(@matchschema);
	($shiftschema) =~ s/\x0D//g;
	my @ARSplitschema=split(/\s:\s/,$shiftschema);
	chomp(@ARSplitschema);
	print "Warehouse Schema=$ARSplitschema[1]\n";
}

my @matchuser=grep(/warehouseUser/,@ARLogarray) or print "Warehouse User ";
if ($#matchuser < 0) {
	print "NOT FOUND.\n";
} else {
	my $shiftuser=pop(@matchuser);
	($shiftuser) =~ s/\x0D//g;
	my @ARSplituser=split(/\s:\s/,$shiftuser);
	chomp(@ARSplituser);
	print "Warehouse UserID=$ARSplituser[1]\n";
}

my @matchmaxworkers=grep(/$searchmaxworkers/i,@ARLogarray) or print "KSY_MAX_WORKER_THREADS setting ";
if ($#matchmaxworkers < 0) {
	print "NOT FOUND.\n";
} else {
	my $shiftmaxworkers=pop(@matchmaxworkers);
	($shiftmaxworkers) =~ s/\x0D//g;
	my @ARSplitmaxworkers=split(/\s:\s/,$shiftmaxworkers);
	chomp(@ARSplitmaxworkers);
	print "KSY_MAX_WORKER_THREADS=$ARSplitmaxworkers[1]\n";
}

my @matchmaxrows=grep(/$searchmaxrows/i,@ARLogarray) or print "KSY_MAX_ROWS_PER_TRANSACTIONS setting ";
if ($#matchmaxrows < 0) {
		print "NOT FOUND.\n"
} else {
	my $shiftmaxrows=pop(@matchmaxrows);
	($shiftmaxrows) =~ s/\x0D//g;
	my @ARSplitmaxrows=split(/\s:\s/,$shiftmaxrows);
	chomp(@ARSplitmaxrows);
	print "KSY_MAX_ROWS_PER_TRANSACTIONS=$ARSplitmaxrows[1]\n";
}

my @matchwarehousejars=grep(/$searchwarehousejars/i,@ARLogarray) or print "WarehouseJars setting ";
if ($#matchwarehousejars < 0) {
	print "NOT FOUND.\n";
} else {
	my $shiftwarehousejars=pop(@matchwarehousejars);
	($shiftwarehousejars) =~ s/\x0D//g;
	my @ARSplitwarehousejars=split(/\s:\s/,$shiftwarehousejars);
	chomp(@ARSplitwarehousejars);
	print "WarehouseJar=$ARSplitwarehousejars[1]\n";
}

my @matchwarehousedriver=grep(/warehouseDriver/,@ARLogarray) or print "Warehouse Driver setting ";
if ($#matchwarehousedriver < 0) {
	print "NOT FOUND.\n";
} else {
	my $shiftwarehousedriver=pop(@matchwarehousedriver);
	($shiftwarehousedriver) =~ s/\x0D//g;
	my @ARSplitwarehousedriver=split(/\s:\s/,$shiftwarehousedriver);
	chomp(@ARSplitwarehousedriver);
	print "Warehouse Driver=$ARSplitwarehousedriver[1]\n";
}

my @matchshiftsenabled=grep(/shiftsEnabled/,@ARLogarray) or my $sShiftsenabled=("none");
if ($#matchshiftsenabled < 0) {
	$sShiftsenabled=("none");
} else {
	my $shiftshiftsenabled=pop(@matchshiftsenabled);
	($shiftshiftsenabled) =~ s/\x0D//g;
	my @ARSplitshiftsenabled=split(/\s:\s/,$shiftshiftsenabled);
	chomp(@ARSplitshiftsenabled);
	print "shiftsEnabled=$ARSplitshiftsenabled[1]\n";
}

my @matchvacationsenabled=grep(/vacationsEnabled/,@ARLogarray) or my $sVacationssenabled=("none");
if ($#matchvacationsenabled < 0) {
	$sVacationssenabled=("none");
} else {
	my $shiftvacationsenabled=pop(@matchvacationsenabled);
	($shiftvacationsenabled) =~ s/\x0D//g;
	my @ARSplitvacationsenabled=split(/\s:\s/,$shiftvacationsenabled);
	chomp(@ARSplitvacationsenabled);
	print "vacationsEnabled=$ARSplitvacationsenabled[1]\n";
}

##################################################################################
# Tables Aggregated and Pruned Information
##################################################################################
print "\n#######################################################\n";
print "Tables/View Processed and the amount of time to process in seconds:\n";
print "grep statement uses>  \"Summarize for\" \n\n";
get_tableprocessinfo();
print "\n**********************************************\n";
my @ARSearchhistconfig=grep(/Summarize\sfor/,@ARLogarray);
if ($#ARSearchhistconfig >= 0) {
	get_histconfig();
}
print "#######################################################\n";

##################################################################################
# Calling Subroutines to locate errors
# Subroutines in this section must be included in Error Section 2 #
##################################################################################
print "\n#######################################################\n";
print "Errors:\n";
err_histconfig();
err_dbsocket();
err_driver();
err_uidpwd();
#err_oraclepreparedstatement();
err_sqlexception();
print "\n#######################################################\n";

print "\n#######################################################\n";
print "Review of $mostrctlog completed.";
print "\n#######################################################\n";

####################################################################
# Checks RAS logs other than the RAS1 log
####################################################################
} else {
print "\n#######################################################\n";
print "\t\t$mostrctlog\n";
print "#######################################################\n";

print "\n#######################################################\n";
print "Tables/View Processed and the amount of time to process in seconds:\n\n";
get_tableprocessinfo();
print "\n**********************************************\n";
get_histconfig();
print "#######################################################\n";

print "\n#######################################################\n";
##################################################################################
# Error Section 2 
##################################################################################
print "Errors:\n";
err_histconfig();
err_dbsocket();
err_driver();
err_uidpwd();
#err_oraclepreparedstatement();
err_sqlexception();
print "\n#######################################################\n";
}

exit(0);

##################################################################################
#####################        Subroutines       ###################################
##################################################################################
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

##################################################################################
#####################        Error Subroutines   #################################
##################################################################################
sub err_sqlexception {
open (LOG,"<$mostrctlog");
my @ARLogarray=<LOG>;
close(LOG);
my $sSqlexception=undef;
my $sThreads=undef;

my @ARtwork=grep(/t=work/,@ARLogarray) or $sSqlexception=("none");
if ($#ARtwork >=0) {
	my @ARsqlexception=grep(/SQLException/i,@ARtwork) or $sSqlexception=("none");
	if  ($#ARsqlexception >= 10) {
		print "\nSQLException Errors:\n";
		open(INSERTS,">reviewras.sqlexceptions");
		foreach $sSqlexception (@ARsqlexception) {
			my ($sTwork_thread) = $sSqlexception =~ m/t=(.*?)\s+/;
			my ($sWorkerThread) ="t=$sTwork_thread";
			my @ARsql_threadsraw=grep(/$sWorkerThread\s/i,@ARLogarray);
			my @ARsql_threads=grep(/Examining|sqlexception/i,@ARsql_threadsraw);
			foreach $sThreads (@ARsql_threads) {
			printf INSERTS $sThreads;
		}
		}
		close(INSERTS);
		open(INSERTFILE,"<reviewras.sqlexceptions");
		open(OUTPUTFILE,">$mostrctlog.reviewras.sqlexceptions");
		while(<INSERTFILE>) {
			s/^\s$//;
			print OUTPUTFILE "$_";
		}
		close("INSERTFILE");
		unlink("reviewras.sqlexceptions");
		close("OUTPUTFILE");
		print "More than 10 \"SQLException errors found in $mostrctlog\n";
		print "SQLException errors stored in file $mostrctlog.reviewras.sqlexceptions\n";
		#print "\n<<<  Solution:  Locate tables causing SQLException using: grep t=work{x} $mostrctlog | grep -i -E \"Examining|SQLException\"  >>>\n";
	        print "\n<<<  Solution:  Locate tables causing SQLException using:\ngrep -E \"^== 2012|t=work<x>\" $mostrctlog | grep -i -E \"Examining|SQLException|Exception|Memory in bytes\" \nNOTE: Confirm \"work\<x\>\" using information in the $mostrctlog.reviewras.sqlexception file. >>>\n";
	} elsif ($#ARsqlexception >=0) {
	
	print "SQLException Errors Found:\n";
		foreach $sSqlexception (@ARsqlexception) {
		my ($sTwork_thread) = $sSqlexception =~ m/t=(.*?)\s+/;
		my ($sWorkerThread) ="t=$sTwork_thread";
		my @ARsql_threadsraw=grep(/$sWorkerThread\s/i,@ARLogarray);
		my @ARsql_threads=grep(/Examining|sqlexception/i,@ARsql_threadsraw);
		foreach $sThreads (@ARsql_threads) {
			print "$sThreads";
		}
		}		
		#print "\n<<<  Solution:  Locate tables causing SQLException using: grep t=work{x} $mostrctlog | grep -i -E \"Examining|SQLException\"  >>>\n";
	        print "\n<<<  Solution:  Locate tables causing SQLException using: grep -E \"^== 2012|t=work<x>\" $mostrctlog | grep -i -E \"Examining|SQLException|Exception|Memory in bytes\"  >>>\n";
	}
}
}

sub err_uidpwd {
open (LOG,"<$mostrctlog");
my @ARLogarray=<LOG>;
close(LOG);
my @ARUidpwd=grep(/\sConnection\sauthorization\sfailure/i,@ARLogarray);
if ($#ARUidpwd >=0) {
	my @ARMatchURL=grep(/Attempting\sconnection\swith\sURL/i,@ARLogarray);
	my $popmatchurl=pop(@ARMatchURL);
	my $popuidpwd=pop(@ARUidpwd);
	print "$popmatchurl";
	print "$popuidpwd";
	if ($sLocalhostos eq "Windows") {
		print "<<<Solution:  Confirm username and password specified in URL are valid.>>>\n";
	} else {
		print color 'bold';
		print "<<<Solution:  Confirm username and password specified in URL are valid.>>>\n";
		print color 'reset';
	}
}	
}

sub err_driver {
open (LOG,"<$mostrctlog");
my @ARLogarray=<LOG>;
close(LOG);
my @ARGetdriver=grep(/No\ssuitable\sdriver/i,@ARLogarray);
if ($#ARGetdriver >=0) {
	my @ARLoaddriver=grep(/\sLoading\sdriver\s:\s\(/i,@ARLogarray);
	my $popdriver=pop(@ARGetdriver);
	chomp($popdriver);
	my $poploaddriver=pop(@ARLoaddriver);
	chomp($poploaddriver);
	print "Attempts to load driver: $poploaddriver\n";
	print "Fails: $popdriver\n";
	if ($sLocalhostos eq "Windows") {
		print "<<< Solution:  Confirm the SY JDBC Driver is correctly specified in the SY configuration. See URL: http://publib.boulder.ibm.com/infocenter/tivihelp/v15r1/index.jsp?topic=/com.ibm.itm.doc_6.2.2fp2/itm_install94.htm >>>\n";
	} else {
		print color 'bold';
		print "<<< Solution:  Confirm the SY JDBC Driver is correctly specified in the SY configuration. See URL: http://publib.boulder.ibm.com/infocenter/tivihelp/v15r1/index.jsp?topic=/com.ibm.itm.doc_6.2.2fp2/itm_install94.htm >>>\n";
		print color 'reset';
	}
}	
}

sub err_histconfig {
my $searchgethistory=("getHistoryConfig request to the TEP Server failed");
open (LOG,"<$mostrctlog");
my @ARLogarray=<LOG>;
close(LOG);
my @ARgethistory=grep(/$searchgethistory/i,@ARLogarray) or my $sHistory=("none");
if ($#ARgethistory >= 0) {
	my $pophistory=pop(@ARgethistory);
	chomp($pophistory);
	if ($sLocalhostos eq "Windows") {
		print "\n$pophistory\n";
		print "<<<Solution:  SY agent failed to connect to TEPS. Confirm TEPS is online and SY Agent can communicate with TEPS.>>>\n";
	} else {
		print "\n$pophistory\n";
		print color 'bold';
		print "<<<Solution:  SY agent failed to connect to TEPS. Confirm TEPS is online and SY Agent can communicate with TEPS.>>>\n";
		print color 'reset';
	}
	
} else {
	$sHistory=("none");
}
}

sub err_dbsocket {
my $searchsocket=("Error opening socket to server ");
open (LOG,"<$mostrctlog");
my @ARLogarray=<LOG>;
close(LOG);
my @ARgetsocket=grep(/$searchsocket\w+(.*?)Connection\srefused/i,@ARLogarray) or my $sSocket=("none");
if ($#ARgetsocket >= 0) {
	my $popsocket=pop(@ARgetsocket);
	chomp($popsocket);
	if ($sLocalhostos eq "Windows") {
		print "\n$popsocket\n";
		print "<<<Solution:  SY agent failed to connect to data warehouse server. Confirm TDW server is online and SY Agent can communicate with TDW server.>>>\n";
	} else {
		print "\n$popsocket\n";
		print color 'bold';
		print "<<<Solution:  SY agent failed to connect to data warehouse server. Confirm TDW server is online and SY Agent can communicate with TDW server.>>>\n";
		print color 'reset';
	}
} else {
	$sSocket=("none");
}
}

#sub err_oraclepreparedstatement {
#my @AROraclepreparedlist=grep(/OraclePreparedStatement.java/i,@ARLogarray);
#if ($#AROraclepreparedlist >= 0) {
#	my $sOracleprepared=pop(@AROraclepreparedlist);
#	print "DEBUG: $sOracleprepared\n"; 
#}
#}



#sub err_outofbounds {
#my $searchoutofbounds=("java.lang.ArrayIndexOutofBoundsException");
#my @AROutofbounds=grep(/$searchoutofbounds/i,@ARLogarray)
#if ($#AROutofbounds >= 0) {
#	my $popoutofbounds=pop(@AROutofbounds);
#	chomp($popoutofbounds);
#	if ($sLocalhostos eq "Windows") {
#		print "\n$popoutofbounds\n";
		#Solution: If the customer is using an Oracle warehouse, check for a stack trace in the log that fails when executing the oracle.jdbc.driver.OraclePreparedStatement.executeBatch() method.  If this is the case then the customer is suffering from Oracle BUG-6396242 and needs to download the Oracle JDBC driver 11.1.0.7.0 or higher.  Reconfigure the S&P to use the new jar file and the problem should go away.
		#The stack trace will look similar to the following:
		#<log_start>
		#== 4649 t=work1 EXCEPTION: Failed to create aggregates for node: (xxxmcds208:KUX)
		#== 4650 t=work1 java.lang.ArrayIndexOutOfBoundsException: -32103 
		#       at oracle.jdbc.driver.OraclePreparedStatement.setupBindBuffers(OraclePreparedStatement.java:2673)
		#        at oracle.jdbc.driver.OraclePreparedStatement.executeBatch(OraclePreparedStatement.java:10689)
		#<log_end>
#	} else {
#		print "\n$popoutofbounds\n";
#		print color 'bold';
		#Solution: If the customer is using an Oracle warehouse, check for a stack trace in the log that fails when executing the oracle.jdbc.driver.OraclePreparedStatement.executeBatch() method.  If this is the case then the customer is suffering from Oracle BUG-6396242 and needs to download the Oracle JDBC driver 11.1.0.7.0 or higher.  Reconfigure the S&P to use the new jar file and the problem should go away.
		#The stack trace will look similar to the following:
		#<log_start>
		#== 4649 t=work1 EXCEPTION: Failed to create aggregates for node: (xxxmcds208:KUX)
		#== 4650 t=work1 java.lang.ArrayIndexOutOfBoundsException: -32103 
		#       at oracle.jdbc.driver.OraclePreparedStatement.setupBindBuffers(OraclePreparedStatement.java:2673)
		#        at oracle.jdbc.driver.OraclePreparedStatement.executeBatch(OraclePreparedStatement.java:10689)
		#<log_end>
#		print color 'reset';
#	}
#}
#}

##################################################################################
sub get_histconfig {
my $sRawline=undef;
open (LOG,"<$mostrctlog");
open (TABHIST,">$mostrctlog.reviewras.histconfig");
while ($sRawline = <LOG> ) {
	if ($sRawline =~ /^\.{12}Table\s/) {
		print TABHIST "$sRawline";
	}
		if ($sRawline =~ /^(\.+(Summarize|Prune).+)/) {
		print TABHIST "$sRawline"; 
		}
}
print "Summarization/Pruning configuration for each table stored in $mostrctlog.reviewras.histconfig\n";
close(LOG);
close(TABHIST);
}

sub get_tableprocessinfo {

my @ARTables=grep(/Elapsed\stime\sin\sms\s:\s/,@ARLogarray);
if ($#ARTables < 0) {
	print "Aggregation/Pruning of tables not found in log.\n";
} else {
	foreach my $sTable(@ARTables) {
	($sTable) =~ s/\x0D//g;

	# Build Time Array
	my @ARsplitTime=split(/\sms\s:\s\(/,$sTable);
	chomp(@ARsplitTime);
	my $sMSTime=$ARsplitTime[1];
	$sMSTime =~ s/\)\sfor(.*)//;
	my $sRawtime=(0.001*$sMSTime);
	my $sTime=sprintf("%.2f",$sRawtime);

 	# Build For All Products Array	
	my @ARsplitprod=split(/\sfor\sall/,$sTable);
	chomp(@ARsplitprod);
		if ($#ARsplitprod > 0 ) {
		$successicount++;
		print "\n........ END of Successful S&P Run Number $successicount .......\n";
 		print "Total time (seconds) for this run: $sTime\n";
		print "---------------------------------------\n\n"; 
		} else {

		# Build Table Array
		my @ARsplittable=split(/:\s+\(/,$sTable);
		chomp(@ARsplitTime);
		my $sSytable=$ARsplittable[2];
		($sSytable) =~ s/\)\stable\s\d+//;
		chop($sSytable);
		print "Table/View: $sSytable process time $sTime\n"; 
		my $sLrtable=("Table $sSytable  $sTime seconds");
		if ($sTime >= $userlongrunning) {
		push(@ARLongrunning,$sLrtable);
		} 
		}
	}

#########################################################################
# Check for EOF before S&P run completes 
#########################################################################
	my @ARPoplogarray=pop(@ARLogarray);
	my @AREof=grep(/Trace\scontinues\sin||^\s$/,@ARPoplogarray);
	if ($#AREof >= 0) {
		print "\n********** End of file reached before S&P run completes. **********\n";
	}
}

	# Build Failed Runs
	my @ARFailed=grep(/\sended\swith\serrors/i,@ARLogarray);
	chomp(@ARFailed);
	if ($#ARFailed > 0) {
	print "\n**********************************************\n";
	print "Total Completed S&P Runs: $successicount\n";
	print "Total Failed S&P Runs: $#ARFailed";
	print "\n**********************************************\n";
	} else {
	print "\n**********************************************\n";
	print "Total Completed S&P Runs: $successicount";
	print "\n**********************************************\n";
	}

	# Print Long Running Tables
	if ($sLocalhostos eq "Windows") {
		if ($#ARLongrunning < 0) {
		print "All tables processed within $userlongrunning seconds\n";
		} else {
		print "Tables that take more than $userlongrunning seconds to process:\n\n";
        	foreach my $sLongrunning(@ARLongrunning) {
		print "$sLongrunning\n";
		}
		}
	} else {
		if ($#ARLongrunning < 0) {
		print "All tables processed within $userlongrunning seconds\n";
		} else {
		print color 'bold';
		print "Tables that take more than $userlongrunning seconds to process:\n\n";
        	foreach my $sLongrunning(@ARLongrunning) {
			print "$sLongrunning\n";
		}
		print color 'reset';
		}
	}
}
