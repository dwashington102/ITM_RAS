#!/usr/bin/perl 
# ior_parser.pl
# Script will parse cnps.ior file gathering the IP address and port number used for TEP client to TEPS communication
#################################################################################
# Date: 2012/08/08
#
# Revision History:
# Revision 0.0.1 2012/08/08
# 	Add ability to pass cnps.ior file to script
# 	Clean up output
#################################################################################
use strict;
#use warnings;
require CORBA::IOP::IOR;

my $ior=undef;

my $cnpsfile=$ARGV[0] or die "Usage: ior_parser.pl [cnps.ior file]\n\n";

$ior = new CORBA::IOP::IOR;
open (CNPS,"<$cnpsfile");
our @ARLogarray=<CNPS>;
close(CNPS);

my @ARConfirmior=grep(/^IOR/,@ARLogarray);
if ($#ARConfirmior < 0) {
	print "\nInvalid IOR file.\n\n"; 
	exit(1);
} else {
my $popCnps=pop(@ARLogarray);

print "\n#######################################################\n";
$ior->parseIOR($popCnps);
$ior->printHash();
#$ior->{IIOP_profile}->{host} = "host.domain.name";
print "\n";
print "Review of $cnpsfile completed.\n";
print "#######################################################\n";
}
exit(0);
