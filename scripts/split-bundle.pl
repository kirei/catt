#!/usr/bin/perl
#
# Split bundle of certificates into files. Output file names set to each
# certificate's SHA-1 fingerprint.

use warnings;
use strict;

my $counter    = 0;
my $processing = 0;
my $filename   = undef;

while (<STDIN>) {

    if (/^-----BEGIN CERTIFICATE-----/) {
        $processing = 1;

        $counter++;

        $filename = sprintf("export-%d.pem", $counter);
        open(EXPORT, "> $filename");
        print EXPORT $_;
        next;
    }

    if (/^-----END CERTIFICATE-----/) {
        $processing = 0;

        print EXPORT $_;
        close(EXPORT);

        my $fp = `openssl x509 -in $filename -noout -fingerprint`;
        chomp $fp;
        $fp =~ s/SHA1 Fingerprint=//;
        $fp =~ s/://g;

        my $subject = `openssl x509 -in $filename -noout -subject`;
        chomp $subject;
        $subject =~ s/subject= //;

        rename($filename, sprintf("%s.pem", $fp));

        print $fp,      "\n";
        print $subject, "\n";
        print "\n";

        next;
    }

    print EXPORT $_ if ($processing);
}
