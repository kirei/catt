#!/usr/bin/perl

use warnings;
use strict;
use Mac::PropertyList qw(:all);
use JSON;

my $plist = "/System/Library/Keychains/EVRoots.plist";
my $data  = Mac::PropertyList::parse_plist_file($plist)->as_perl;

my $ev;
my $count = 0;

foreach my $oid (keys %{$data}) {

    foreach my $fp (@{ $data->{$oid} }) {
        $ev->{$count} = {
            "oid"         => $oid,
            "fingerprint" => unpack("H*", $fp)
        };
        $count++;
    }
}

print encode_json($ev);
