#!/usr/bin/perl 
# rasquery.pl
# Script searchs the TEPS RAS log for queries made against the TEPS,TEMS, and WAREHOUSE databases.
# User can then decided which queries they would like to see
# Once the type of query is selected, the script will gather all queries
# matching query type and write to a the file reviewras.queries
#################################################################################
#										
# Date: 2010/08/21
#
# Revision History:
# Revision 1.1a 20/17: Corrected d-20101117a.
#
# Revision 1.1 2010/09/15:
#	added check_filename() - confirms file passed is valid
#
# Revision 1.0 2010/02/01					
#################################################################################
# Defects Found:
# 2010/11/17:
# d-20101117a - @ARmatch incorrectly finds non-query requests. 
#	Added @ARCtsqlmatch to parse out CTSQL queries
#################################################################################

use strict;
use warnings;
use Cwd;

my $mostrctlog=$ARGV[0] or die "Usage: rasquery.pl [RAS LOG]\n\n";
check_filename();
unlink("rawlist.txt");

print "Searching for query labels...\n";
open(LOG,"<$mostrctlog");
my @ARlogarray =  <LOG>;
close(LOG);

my @ARCtsqlmatch=grep(/CTSQL/,@ARlogarray) or die "Unable to locate and queries within $mostrctlog\n\n"; 
my @ARmatch=grep(/\w+\(\d+\):/,@ARCtsqlmatch) or die "Unable to locate and queries within $mostrctlog\n\n"; 
#my @ARmatch=grep(/\w+\(\d+\):/,@ARlogarray) or die "Unable to locate and queries within $mostrctlog\n\n"; 
foreach my $sQuerymatch(@ARmatch) {
	print "..\r";
	my $sDBNAME=undef;
	undef my @ARDbname;
	($sDBNAME) = $sQuerymatch =~ m/\"\)\s(.*?)\(/;	
	push(@ARDbname,"$sDBNAME");
	open(OUTPUT,">>rawlist.txt");
	print OUTPUT "@ARDbname\n";
	print "...\r";
	close(OUTPUT);
}
dblabels();
close(OUTPUTLOG);
unlink("rawlist.txt");
exit(0);

##################################################################################
#######################        Subroutines     ###################################
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

sub dblabels {
	my $mostrctlog=$ARGV[0];
	open(RAWDATA,"<rawlist.txt");
	my @ARRaw=<RAWDATA>;
	close(RAWDATA);
	my %hSORT=();
	my %hDBLABEL=();
	undef my @ARHash;
	@ARRaw=grep ++$hSORT{$_} < 2, @ARRaw;
	my $iloopforeach=1;
	foreach my $sDbname(@ARRaw) {
	print "[$iloopforeach] $sDbname";
	push(@ARHash,"$iloopforeach","$sDbname");
	$iloopforeach++;
	}
	%hDBLABEL=(@ARHash);
	print "Choose the number preceding the database name to gather all queries within RAS log for that database: \t";
	my $sDb=<STDIN>;
	chomp($sDb);
	if ($sDb !~ /^\d+$/) {
		print "Insert a numeric value.\n";
		unlink("rawlist.txt");
		exit(-1);
	} elsif ($sDb < 1||$sDb >= $iloopforeach) {
		print "Invalid selection. Run rasquery.pl again and pass a valid database choice.\n";
		unlink("rawlist.txt");
		exit(-1);
	} else {
	print "Gathering all queries for database: ",$hDBLABEL{$sDb},"\n";
	my $sDbquery = $hDBLABEL{$sDb};
	chop($sDbquery);
	open(LOG,"<$mostrctlog");
	my @ARlogarray =  <LOG>;
	close(LOG);
	my @ARDbmatch=grep(/$sDbquery\(\d+\):/i,@ARlogarray);
	unlink("$mostrctlog.reviewras.queries_$sDbquery");
	open(OUTPUTLOG,">$mostrctlog.reviewras.queries_$sDbquery");
	foreach my $sARDbmatch(@ARDbmatch) {
	print OUTPUTLOG "$sARDbmatch\n";
	}
	print "Queries for $sDbquery written to $mostrctlog.reviewras.queries\_$sDbquery.\n\n";
	system ("convertras.pl $mostrctlog.reviewras.queries\_$sDbquery");
	}
}
