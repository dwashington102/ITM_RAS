#!/usr/bin/perl -w
# reviewras.pl
#------------------------------------------------------------------------------
# Licensed Materials - Property of IBM (C) Copyright IBM Corp. 2010, 2010
# All Rights Reserved US Government Users Restricted Rights - Use, duplication
# or disclosure restricted by GSA ADP Schedule Contract with IBM Corp
#------------------------------------------------------------------------------
# Script is AS-IS and not supported by IBM Support.
#------------------------------------------------------------------------------
# Script locates most recent RAS1 log in the current directory and call the appopriate
# Perl script to parse the RAS1 log.
#################################################################################
#										
# Date: 2010/08/21
#
# Revision History:
# Revision 1.7 2013/12/11
# 	Corrected grep statement in get_ras1() to detect files with naming convention <hostname>_HD_52ab008e-1.log:
#	Changed: 	my @ARlistoffiles = grep(/\_$sPC\_[4-9].-1.log$|\_$sPC\_[4-9].*-01.log$/i,readdir(DIR)) or die "[1] Unable to locate $sPC RAS1 logs.\nLaunch reviewras.pl from directory where RAS logs reside.\n\n";
#
#	To: 	my @ARlistoffiles = grep(/\_$sPC\_[4-9].*-1.log$|\_$sPC\_[4-9].*-01.log$/i,readdir(DIR)) or die "[1] Unable to locate $sPC RAS1 logs.\nLaunch reviewras.pl from directory where RAS logs reside.\n\n";

#	
# Revision 1.6 2012/09/01 
#	Corrected d-20120901 changing UX/LX search from 
#} elsif (($sPC eq "UX")||($sPC eq "ux")||($sPC eq "LZ")||($sPC eq "lz")) {
#  to
#} elsif (($sPC eq "UX")||($sPC eq "ux")||($sPC eq "LZ")||($sPC eq "lz")||($sPC eq "px")||($sPC eq "PX")) {
# 
# 	Corrected d-20120901a changing
#	my @ARlistoffiles = grep(/\_$sPC\_k$sPC$sAgent\_[4-9].*-1.log$|\_$sPC\_k$sPC$sAgent\_[4-9].*-01.log/i,readdir(DIR)) or die "[3] Unable to locate $sPC RAS1 logs.\nLaunch reviewras.pl from directory where RAS logs reside.\n\n";
# 	to
#	my @ARlistoffiles = grep(/\_$sPC\_k$sPC$sAgent\_[4-9].*-1.log$|\_$sPC\_k$sPC$sAgent\_[4-9].*-01.log$/i,readdir(DIR)) or die "[3] Unable to locate $sPC RAS1 logs.\nLaunch reviewras.pl from directory where RAS logs reside.\n\n";
#
# Revision 1.5 2012/07/12
#	Changed all searches for _4.*.log to _[4-9].*.log in order to handle change in hextime
# Revision 1.4 2012/05/05 (Happy Cinco de Mayo!)
# 	Changed all @ARsortfiles in order to correct issue where logs arrive with same timestamps.
#	Testing using @ARsortfiles for Windows NT OS agent
#
# Revision 1.3 2011/11/20
#	Changed get_ras1() to search for cq_KfwServices as ITM6 TEPS RAS1 log can now be either
#	hostname_cq_4*1.log
#	 or
#	hostname_cq_KfwServices_4*1.log
#
# Revision 1.2 2010/09/22
#	added convert_systemout()
#	added lines to test and call convert_systemout()
#	> } elsif (($sPC eq "systemout")||($sPC eq "systemout.log")||($sPC eq "SystemOut.log")||($sPC eq "SystemOut")) {
#	> convert_systemout();
#	added elsif ($sPC eq "SystemOut.log") to call ewasreview.pl for SystemOut.log
#	
# Revision 1.1 2010/09/14
# 	added 0 byte filesize checking prior to calling Perl parsing script
#
# Revision 1.0 2010/02/01					
#################################################################################
# Defects:
# 2012/09/01: - 
# 	d-20120901 Script fails to locate PX Agent logs
#	d-20120901a Script includes all *_px_{HEX}-01.log files rather than only *_px_{HEX}-01.log$
#
# 2012/03/01: - Script includes all *_cq_4*.log files rather than only *_cq_4*.log$ files.
# 2012/02/01: (Working)
# d-20120201a - Script fails to correctly order logs (LZ OS Agent) when RAS logs all contain same date timestamp, but different times of the day.
#
# 2010/11/12: 
# d-20101112a - When RAS log includes *_<prod.id>_4*-11.log, reviewras grabs logs #11 instead of RAS 1.
# Corrected search
# Replaced: my @ARlistoffiles = grep(/\_$sPC\_4.*1.log$/i,readdir(DIR)) or die "[1] Unable to locate $sPC RAS1 logs.\nLaunch reviewras.pl from directory where RAS logs reside.\n\n";
# With: my @ARlistoffiles = grep(/\_$sPC\_4.*-1.log$|\_$sPC\_4.*-01/i,readdir(DIR)) or die "[1] Unable to locate $sPC RAS1 logs.\nLaunch reviewras.pl from directory where RAS logs reside.\n\n";
#
#################################################################################

use strict;
use warnings;
use Cwd;

##################################################################################
#######################     Set Variables      ###################################
##################################################################################
my $currentdir=cwd;
my $sAgent='agent';
my $sPC=undef;

##################################################################################
#######################        Main Program    ###################################
##################################################################################

if ($#ARGV >= 0) {
	# Takes product code passed via CLI with script name.
	chomp ($ARGV[0]);
	$sPC="$ARGV[0]";
	chomp($sPC);
	if (($sPC eq "syjava")||($sPC eq "SYJAVA"||$sPC eq "SY"||$sPC eq "sy")) {
		convert_syjava();
	} elsif (($sPC eq "systemout.log")||($sPC eq "SystemOut.log")||($sPC eq "systemout")||($sPC eq "SystemOut")) {
		convert_systemout();
	
	} else {
		test_pclength();
	}
} else {
	# Prompts user for product code if product code is not passed along with script name.
	print "Enter Product Code: ";
	$sPC = <STDIN>;
	chomp($sPC);
	if (($sPC eq "syjava")||($sPC eq "SYJAVA"||$sPC eq "SY"||$sPC eq "sy")) {
		convert_syjava();
	} elsif (($sPC eq "systemout")||($sPC eq "systemout.log")||($sPC eq "SystemOut.log")||($sPC eq "SystemOut")) {
		convert_systemout();
	} else {
		test_pclength();
	}
}

opendir(DIR, $currentdir) or die "Could not open the current directory.\n";
my @ARlistoffiles = grep(/(\_$sPC.*\_[4-9].*.log$)||($sPC)/i,readdir(DIR)) or die "[0] Could not locate RAS logfiles for product code $sPC.\n";
closedir(DIR);
get_ras1();
exit (0);


##################################################################################
#######################        Subroutines     ###################################
##################################################################################

sub convert_syjava {
if (($sPC eq "syjava")||($sPC eq "SYJAVA"||$sPC eq "SY"||$sPC eq "sy")) {
	$sPC="sy_java"; 
} 
}

sub convert_systemout {
if (($sPC eq "systemout.log")||($sPC eq "SystemOut.log")||($sPC eq "systemout")||($sPC eq "SystemOut")) {
	$sPC="SystemOut.log";
}
}

sub test_pclength {
my $testPC=length($sPC);
if ($sPC ne "sy_java") {
	if ($testPC != 2) {
	print "Invalid Product Code.\n";
	print "Valid Product Codes (examples):\n\tCQ=TEPS\n\tMS=TEMS\n\tHD=Warehouse Proxy Agent\n\tsyjava=SY Java logs\n\tOS Agent codes (UX, LX, NT)\n\tsystemout=SystemOut.log\n";
	exit (1);
	} 
}
}

sub get_ras1 {
if (($sPC eq "HD")||($sPC eq "hd")||($sPC eq "MS")||($sPC eq "ms")||($sPC eq "sy_java")) {
#if (($sPC eq "CQ")||($sPC eq "cq")||($sPC eq "HD")||($sPC eq "hd")||($sPC eq "MS")||($sPC eq "ms")||($sPC eq "sy_java")) {
	opendir(DIR, $currentdir) or die "Could not open the current directory.\n";
	my @ARlistoffiles = grep(/\_$sPC\_[4-9].*-1.log$|\_$sPC\_[4-9].*-01.log$/i,readdir(DIR)) or die "[1] Unable to locate $sPC RAS1 logs.\nLaunch reviewras.pl from directory where RAS logs reside.\n\n";
	#my @ARlistoffiles = grep(/\_$sPC\_4.*1.log$/i,readdir(DIR)) or die "[1] Unable to locate $sPC RAS1 logs.\nLaunch reviewras.pl from directory where RAS logs reside.\n\n";
	closedir(DIR);
	#my @ARsortfiles = sort {-M $a <=> -M $b} @ARlistoffiles;
	my @ARsortfiles = sort {lc $b cmp lc $a} @ARlistoffiles;
	my $mostrctlog=shift(@ARsortfiles);
	if (($sPC eq "MS")||($sPC eq "ms")) {
		if (-z $mostrctlog) {
			print "File $mostrctlog is 0 bytes.\n";
		} else {
		system("temsreview.pl $mostrctlog");
		}
	} elsif ($sPC eq "sy_java") {
		if (-z $mostrctlog) {
			print "File $mostrctlog is 0 bytes.\n";
		} else {
			system("syjavareview.pl $mostrctlog");
		}
	} else {
		if (-z $mostrctlog) {
			print "File $mostrctlog is 0 bytes.\n";
		} else {
			system("wpareview.pl $mostrctlog");
		}
	}
} elsif (($sPC eq "cq")||($sPC eq "CQ")) {
	opendir(DIR, $currentdir) or die "Could not open the current directory.\n";
  	my @ARlistoffiles = grep(/\_cq\_[4-9].*1.log$|\_cq\_KfwServices\_[4-9].*1.log$/i,readdir(DIR)) or die "[2] Unable to locate $sPC RAS1 logs.\nLaunch reviewras.pl from directory where RAS logs reside.\n\n";
	#my @ARlistoffiles = grep(/\_nt_kntcma\_4.*1.log$/i,readdir(DIR)) or die "[2] Unable to locate Windows OS Agent RAS1 logs.\nLaunch reviewras.pl from directory where RAS logs reside.\n\n";
	closedir(DIR);
	#my @ARsortfiles = sort {-M $a <=> -M $b} @ARlistoffiles;
	my @ARsortfiles = sort {lc $b cmp lc $a} @ARlistoffiles;
	my $mostrctlog=shift(@ARsortfiles);
	if (-z $mostrctlog) {
		print "File $mostrctlog is 0 bytes.\n";
	} else {
	system("tepsreview.pl $mostrctlog");
	}

} elsif (($sPC eq "nt")||($sPC eq "NT")) {
	opendir(DIR, $currentdir) or die "Could not open the current directory.\n";
  	my @ARlistoffiles = grep(/\_nt_kntcma\_[4-9].*-1.log$|\_nt_kntcma\_[4-9].*-01.log$/i,readdir(DIR)) or die "[2] Unable to locate $sPC RAS1 logs.\nLaunch reviewras.pl from directory where RAS logs reside.\n\n";
	closedir(DIR);
	#my @ARsortfiles = sort {-M $a <=> -M $b} @ARlistoffiles;
	my @ARsortfiles = sort {lc $b cmp lc $a} @ARlistoffiles;
	my $mostrctlog=shift(@ARsortfiles);
	if (-z $mostrctlog) {
		print "File $mostrctlog is 0 bytes.\n";
	} else {
	system("agentreview.pl $mostrctlog");
	}

} elsif (($sPC eq "UX")||($sPC eq "ux")||($sPC eq "LZ")||($sPC eq "lz")||($sPC eq "px")||($sPC eq "PX")) {
	opendir(DIR, $currentdir) or die "Could not open the current directory.\n";
	my @ARlistoffiles = grep(/\_$sPC\_k$sPC$sAgent\_[4-9].*-1.log$|\_$sPC\_k$sPC$sAgent\_[4-9].*-01.log$/i,readdir(DIR)) or die "[3] Unable to locate $sPC RAS1 logs.\nLaunch reviewras.pl from directory where RAS logs reside.\n\n";
	#my @ARlistoffiles = grep(/\_$sPC\_k$sPC$sAgent\_4.*1.log$/i,readdir(DIR)) or die "[3] Unable to locate $sPC OS Agent RAS1 logs.\nLaunch reviewras.pl from directory where RAS logs reside.\n\n";
	closedir(DIR);
	#my @ARsortfiles = sort {-M $a <=> -M $b} @ARlistoffiles;
	my @ARsortfiles = sort {lc $b cmp lc $a} @ARlistoffiles;
	my $mostrctlog=shift(@ARsortfiles);
	if (-z $mostrctlog) {
		print "File $mostrctlog is 0 bytes.\n";
	} else {
	system("agentreview.pl $mostrctlog");
	}

} elsif ($sPC eq "SystemOut.log") {
	opendir(DIR, $currentdir) or die "Could not open the current directory.\n";
	my @ARlistoffiles = grep(/$sPC/i,readdir(DIR)) or die "[4] Unable to locate $sPC log file.\nLaunch reviewras.pl from directory where $sPC log reside.\n\n";
	closedir(DIR);
	my @ARsortfiles = sort {lc $b cmp lc $a} @ARlistoffiles;
	#my @ARsortfiles = sort {-M $a <=> -M $b} @ARlistoffiles;
	my $mostrctlog=shift(@ARsortfiles);
	if (-z $mostrctlog) {
		print "File $mostrctlog is 0 bytes.\n";
	} else {
		system("ewasreview.pl $mostrctlog");
	}	

} else {
	opendir(DIR, $currentdir) or die "Could not open the current directory.\n";
	my @ARlistoffiles = grep(/\_$sPC\_[4-9].*-1.log$|\_$sPC\_[4-9].*-01.log$/i,readdir(DIR)) or die "[9] Unable to locate $sPC RAS1 logs.\nLaunch reviewras.pl from directory where RAS logs reside.\n\n";
	#my @ARlistoffiles = grep(/\_$sPC.*\_4.*1.log$/i,readdir(DIR)) or die "[9] Could not locate RAS1 logfiles for product code $sPC.\n";
	closedir(DIR);
	my @ARsortfiles = sort {lc $b cmp lc $a} @ARlistoffiles;
	#my @ARsortfiles = sort {-M $a <=> -M $b} @ARlistoffiles;
	my $mostrctlog=shift(@ARsortfiles);
	if (-z $mostrctlog) {
		print "File $mostrctlog is 0 bytes.\n";
	} else {
	system("agentreview.pl $mostrctlog");
	}
}
}

