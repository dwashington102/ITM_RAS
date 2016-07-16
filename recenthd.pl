#!/usr/bin/perl -w
# recenthd.pl
# Script locates the most recent TEPS RAS1 log in the current directory.
#################################################################################
#										
# Date: 2012/02/28
#
# Revision History:
# Revision 1.2 2012/05/04
# 	Changed @ARsortfiles in order to avoid the problem where filenames have the same timestamp.
#################################################################################

use strict;
use Cwd;
use File::stat;

my $currentdir=cwd;
my $mostrctlog=undef;
my $sStat=undef;

format =
=================================================================
| Most recent RAS1 log			      			|
|	 @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<       	|
         $mostrctlog
=================================================================
.

# Undefined
my $sFilename=undef;
undef my @ARlistoffiles;

opendir(DIR, $currentdir) or die "Could not open the current directory.\n";
@ARlistoffiles = grep(/\_hd\_[4-9].*1.log$/i,readdir(DIR)) or die "Unable to locate WPA logs in current directory.\n\n";
closedir(DIR);

my @ARsortfiles = reverse sort {lc $b cmp lc $a} @ARlistoffiles;
#my @ARsortfiles = sort {-M $b <=> -M $a} @ARlistoffiles;

foreach $sFilename (@ARsortfiles) {
	print "$sFilename\t";
	my $sStat=stat($sFilename);
	print scalar localtime $sStat->mtime,"\n";
}

$mostrctlog=pop(@ARsortfiles);
write;
exit (0);
