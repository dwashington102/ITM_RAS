#!/usr/bin/perl -w
#convertras.pl
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
#################################################################################
# Date: 2010/08/21
#
# Revision History:

use strict;
use warnings;
use Cwd;


my $sHextime=undef;
my $sCurrentfile=".reviewras.converted";
undef my @ARlogarray;
undef my @ARHextime;

my $sFilename=$ARGV[0] or die "Usage: convertras.pl [RAS LOG]\n\n";
chomp $sFilename;

# Delete any previous reviewras.converted files generated from same RAS log.
unlink("$sFilename$sCurrentfile");

print "Converting HEX timestamps for the $sFilename...\n";
open(LOG,"<$sFilename");
@ARlogarray = <LOG>;
@ARHextime = grep(/^(.)([\dA-F]+)/, @ARlogarray);
close(LOG);
foreach $sHextime (@ARHextime) {
	if ($sHextime =~ /^(.)([\dA-F]+)(\..*)/) {
	open(HEXTIME, ">>$sFilename.reviewras.converted") || Error('open','file');
	printf HEXTIME ("%s%s%s\n", $1, scalar(localtime(oct("0x$2"))),$3);
	#printf HEXTIME ("%s%s%s\n", $1, scalar(gmtime(oct("0x$2"))),$3);
	close HEXTIME;
	}
	else {
	print "Unable to convert hex timestamp.\n";
	}
}

print "Converted file created $sFilename$sCurrentfile\n";
exit (0);
