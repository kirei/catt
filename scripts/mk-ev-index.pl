#/usr/bin/perl

use warnings;
use strict;
use JSON;

my $json;

while (<>) {
    chomp;
    $json .= $_;
}

my $ev = from_json($json, { utf8 => 1 });

my @index;

foreach my $id (keys %{$ev}) {
    unless ($ev->{$id}->{fingerprint} =~ /^[a-z0-9]{40}$/) {
        printf STDERR ("Bad fingerprint %s\n", $ev->{$id}->{fingerprint});
        next;
    }
    push @index,
      sprintf("%s %s", uc($ev->{$id}->{fingerprint}), $ev->{$id}->{oid});
}

print join("\n", sort @index), "\n";
