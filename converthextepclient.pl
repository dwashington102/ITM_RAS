#!/usr/bin/perl -w
#converthextepclient.pl
# Script to convert hextime in TEP client log to GMT time. 
#################################################################################
# Date: 2010/11/20
#
# Revision History:
# Revision 1.0 2010/11/20:
#################################################################################
# Defects:
#
#################################################################################
use strict;
use warnings;
use Cwd;

my $sLine=undef;
my $sOutputfile=".reviewras.converted";
undef my @ARHextime;

my $sFilename=$ARGV[0] or die "Usage: converthextepclient.pl [TEP Client LOG]\n\n";
chomp $sFilename;
check_filename();

unlink("$sFilename$sOutputfile");
unlink("$sFilename.converted");

print "\nConverting HEX timestamps for $sFilename...\n";
open(LOG,"<$sFilename");
my @ARlogarray =<LOG>;
close(LOG);
foreach $sLine (@ARlogarray) {
	if ($sLine =~ /^(.)([\da-f]+)(\..*)/) {
	open(HEXTIME, ">>$sFilename$sOutputfile") || Error('open','file');
	printf HEXTIME ("%s%s%s\n", $1, scalar(gmtime(oct("0x$2"))),$3);
	close HEXTIME;
	} else {
	open(HEXTIME, ">>$sFilename$sOutputfile") || Error('open','file');
	print HEXTIME ("$sLine");
	close HEXTIME;
	}
}

#Strips CONTROL-M from file
open(INSERTFILE,"<$sFilename$sOutputfile");
open(OUTPUTFILE,">$sFilename.converted");
while(<INSERTFILE>) {
	s/^\s$//;
	s/\x0D//g;
	print OUTPUTFILE "$_";
}

print "\nCreated converted file: $sFilename.converted\n";
print "Times are listed in GMT time.\n";
exit (0);

##################################################################################
#######################        Subroutines     ###################################
##################################################################################
sub check_filename {
if (-z $sFilename) {
	print "File $sFilename is 0 bytes\n";
	exit (1);
} elsif (!-e $sFilename) {
	print "File $sFilename does not exists\n";
	exit (-1);
} elsif (!-r $sFilename) {
	print "Permission denied on access of $sFilename\n";
	exit (-1);
} elsif  ((-e $sFilename) && (-T $sFilename))  {
	chomp $sFilename;
} else {
	print "Unable to process $sFilename.\n";	
}
}

