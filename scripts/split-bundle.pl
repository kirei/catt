#!/usr/bin/perl
#
# Copyright (c) 2013 Kirei AB. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
######################################################################

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
