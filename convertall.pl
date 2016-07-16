#!/usr/bin/perl -w

use strict;
use Cwd;

my $currentdir=cwd;

# Undefined
my $sFilename=undef;
my $sHextime=undef;
undef my @ARHextime;

print "\nEnter Product Code:\t";
my $sPC = <STDIN>;
chomp($sPC);
print "\nEnter TIMESTAMP :\t";
my $sTimestamp = <STDIN>;
chomp($sTimestamp);

opendir(DIR, $currentdir) or die "Could not open current directory.\n";
my @ARlistoffiles = grep(/.*$sPC.*_$sTimestamp-.*.log/i,readdir(DIR)) or die "Unable to locate RAS logs.\n";
closedir(DIR);

foreach $sFilename (@ARlistoffiles) {
	print "Converting Filename: $sFilename...\n";
	chomp($sFilename);
	open (LOG,"<$sFilename");
	my @ARlogarray = <LOG>;
	my @ARHextime = grep(/^(.)([\dA-F]+)/, @ARlogarray);
	foreach $sHextime (@ARHextime) {
		if ($sHextime =~ /^(.)([\dA-F]+)(\..*)/) {
		open(HEXTIME, ">>$sFilename.reviewras.converted") || Error('open','file');
		printf HEXTIME ("%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3);
		close HEXTIME;
		}
		else {
		print "Timestamps within $sFilename cannot be converted.\n";
		}
	}
}
exit (0);
