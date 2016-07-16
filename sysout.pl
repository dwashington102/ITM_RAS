#!/usr/bin/perl 
# sysout.pl

use strict;
use warnings;
use Term::ANSIColor;
use Cwd;

my $currentdir=cwd;
my $sError=undef;
my $sErrorcode=undef;
my $sDate=undef;

undef my @ARError_list=undef;

##################################################################################
#######################        Main Program    ###################################
##################################################################################
my $mostrctlog=$ARGV[0] or die "Usage: sysout SystemOut.log\n\n";
check_filename();
open (LOG,"<$mostrctlog");
our @ARLogarray =  <LOG>;
close(LOG);

@ARError_list=grep(/[A-Z](\w){3}(\d){3}E/,@ARLogarray) or print "No Errors found.\n\n";
#@ARError_list=grep(/[A-Z](\w){3}(\d){3}[E|W]/,@ARLogarray) or print "No Errors found.\n\n";
chomp(@ARError_list);

if ($#ARError_list >= 0) {
	foreach $sError(@ARError_list) {
		my ($sError_code) = $sError =~ m/\s([A-Z](\w){3}(\d){3}[E|W]):/;
		# Below using $` to get the line that preceeds matches of CWWIM4512E
		if ($sError =~ /CWWIM4512E/) {
			#($sDate) = $sError =~ m/^\[(.*?)\]\s/;
			print "$`","$sError","\n";
		} else {	
			print "$sError\n";
		}
	}
}
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
} else {
	print "Unable to process $mostrctlog.\n";	
}
}
