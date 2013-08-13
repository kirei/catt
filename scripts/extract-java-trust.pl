#!/usr/bin/perl
#
# Extract all trusted CAs from JAVA certificate store

use warnings;
use strict;

my $keystore =
"/System/Library/Java/Support/CoreDeploy.bundle/Contents/Home/lib/security/cacerts";
$keystore = $ARGV[0] if ($#ARGV >= 0);

my $keytool =
  sprintf("keytool -keystore \"%s\" -storepass changeit", $keystore);

my @aliases;

die "Failed to read keystore" unless (-r $keystore);

open(CERTLIST, "$keytool -list |");
while (<CERTLIST>) {
    next unless /trustedCertEntry/;
    my @tmp = split(/,/, $_);
    push @aliases, $tmp[0];
}
close(CERTLIST);

foreach my $alias (@aliases) {
    printf STDERR ("Exporting %s\n", $alias);
    system("$keytool -exportcert -alias $alias | openssl x509 -inform der");
}
