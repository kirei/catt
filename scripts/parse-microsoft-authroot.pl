#!/usr/bin/perl
#
# Source: http://kouettland.com/MicrosoftRootProgram.tgz
# Author: Erwann Abalea (twitter @eabalea)
#
# Copyright (c) 2013 Erwann Abalea. All rights reserved.
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

use strict;
use utf8;

use Convert::ASN1 qw(:io :debug);
use JSON;

# ASN.1 descriptions of the objects we're going to parse
my $asn = Convert::ASN1->new;
$asn->prepare(<<ASN1) or die "prepare: ", $asn->error;
   CTL ::= SEQUENCE {
     dummy1 ANY,
     UnknownInt INTEGER,
     GenDate UTCTime,
     dummy4 ANY,
     InnerCTL SEQUENCE OF CTLEntry
   }

   CTLEntry ::= SEQUENCE {
     CertID OCTET STRING,
     MetaData SET OF CertMetaData
   }

   CertMetaData ::= SEQUENCE {
     MetaDataType OBJECT IDENTIFIER,
     MetaDataValue SET {
       RealContent OCTET STRING
     }
   }

   EKUS ::= SEQUENCE OF OBJECT IDENTIFIER

   EVOIDS ::= SEQUENCE OF PolicyThing
   
   PolicyThing ::= SEQUENCE {
     EVOID OBJECT IDENTIFIER,
     dummy5 ANY
   }

ASN1

# Get a handle on particular ASN.1 objects decoders
my $asn_ctl      = $asn->find('CTL');
my $asn_ctlentry = $asn->find('CTLEntry');
my $asn_ekus     = $asn->find('EKUS');
my $asn_evoids   = $asn->find('EVOIDS');
my $object       = "";

# Read the whole CTL as a blob
while (<>) {
    $object = $object . $_;
}

# And try to decode it
my $ctl = $asn_ctl->decode($object);

if (defined $ctl) {

    # Delete unknown fields, and transform others
    delete $ctl->{'dummy1'};
    delete $ctl->{'dummy4'};
    $ctl->{'UnknownInt'} = uc($ctl->{'UnknownInt'}->as_hex());
    $ctl->{'GenDate'}    = scalar gmtime($ctl->{'GenDate'});

    my @Entries = @{ $ctl->{'InnerCTL'} };

    # Display the number of entries. Remove it if you really need to
    # parse the JSON output
    print STDERR "Entries: ", $#Entries, "\n";

    # We'll alter every CTL entry
    foreach my $Entry (@Entries) {

        # The CertID can be used to get the certificate
        my $CertID = uc(unpack("H*", $Entry->{'CertID'}));
        $Entry->{'CertID'} = $CertID;
        $Entry->{'URLToCert'} =
"http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/"
          . $CertID . ".crt";

        # A set of properties is attached to every CTL entry, make them
        # more easily readable
        foreach my $MD (@{ $Entry->{'MetaData'} }) {

            # OID_CERT_PROP_ID_METAEKUS
            if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.9") {
                my $ekus =
                  $asn_ekus->decode($MD->{'MetaDataValue'}->{'RealContent'});
                foreach my $eku (@$ekus) {
                    $eku = "id-kp-serverAuth"  if ($eku eq "1.3.6.1.5.5.7.3.1");
                    $eku = "id-kp-clientAuth"  if ($eku eq "1.3.6.1.5.5.7.3.2");
                    $eku = "id-kp-codeSigning" if ($eku eq "1.3.6.1.5.5.7.3.3");
                    $eku = "id-kp-emailProtection"
                      if ($eku eq "1.3.6.1.5.5.7.3.4");
                    $eku = "id-kp-ipsecEndSystem"
                      if ($eku eq "1.3.6.1.5.5.7.3.5");
                    $eku = "id-kp-ipsecTunnel" if ($eku eq "1.3.6.1.5.5.7.3.6");
                    $eku = "id-kp-ipsecUser"   if ($eku eq "1.3.6.1.5.5.7.3.7");
                    $eku = "id-kp-timeStamping"
                      if ($eku eq "1.3.6.1.5.5.7.3.8");
                    $eku = "id-kp-ocspSigning" if ($eku eq "1.3.6.1.5.5.7.3.9");
                    $eku = "iKEIntermediate"   if ($eku eq "1.3.6.1.5.5.8.2.2");

                    $eku = "ms-EFS-CRYPTO"
                      if ($eku eq "1.3.6.1.4.1.311.10.3.4");
                    $eku = "ms-EFS-RECOVERY"
                      if ($eku eq "1.3.6.1.4.1.311.10.3.4.1");
                    $eku = "ms-DOCUMENT-SIGNING"
                      if ($eku eq "1.3.6.1.4.1.311.10.3.12");
                    $eku = "ms-smartCardLogon"
                      if ($eku eq "1.3.6.1.4.1.311.20.2.2");
                }
                $MD->{'MetaEKUS'} = $ekus;
                delete $MD->{'MetaDataType'};
                delete $MD->{'MetaDataValue'};
            }

            # CERT_FRIENDLY_NAME_PROP_ID
            if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.11") {
                my $CertFriendlyName = $MD->{'MetaDataValue'}->{'RealContent'};
                $CertFriendlyName =~ s/\x00$//g;
                $MD->{'CertFriendlyName'} = $CertFriendlyName;
                delete $MD->{'MetaDataType'};
                delete $MD->{'MetaDataValue'};
            }

            # OID_CERT_KEY_IDENTIFIER_PROP_ID
            if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.20") {
                my $CertKeyIdentifier =
                  uc(unpack("H*", $MD->{'MetaDataValue'}->{'RealContent'}));
                $MD->{'CertKeyIdentifier'} = $CertKeyIdentifier;
                delete $MD->{'MetaDataType'};
                delete $MD->{'MetaDataValue'};
            }

            # OID_CERT_SUBJECT_NAME_MD5_HASH_PROP_ID
            if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.29") {
                my $CertSubjectNameMD5Hash =
                  uc(unpack("H*", $MD->{'MetaDataValue'}->{'RealContent'}));
                $MD->{'CertSubjectNameMD5Hash'} = $CertSubjectNameMD5Hash;
                delete $MD->{'MetaDataType'};
                delete $MD->{'MetaDataValue'};
            }

            # CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID
            if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.83") {

                # I think the "dummy5" element is here to indicate what type
                # of policy the OID is. Right now, I have encountered the same
                # value everywhere, and the OIDs are EV ones; let's ignore
                # "dummy5" and consider all these OIDs are EV ones.
                my @evoids;
                my $Thing =
                  $asn_evoids->decode($MD->{'MetaDataValue'}->{'RealContent'});
                foreach my $policyprop (@$Thing) {
                    push @evoids, $policyprop->{'EVOID'};
                }
                $MD->{'EVOIDS'} = \@evoids;
                delete $MD->{'MetaDataType'};
                delete $MD->{'MetaDataValue'};
            }

            # OID_CERT_PROP_ID_PREFIX_98
            if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.98") {
                my $Thing =
                  uc(unpack("H*", $MD->{'MetaDataValue'}->{'RealContent'}));
                $MD->{'PropID98'} = $Thing;
                delete $MD->{'MetaDataType'};
                delete $MD->{'MetaDataValue'};
            }

            # OID_CERT_PROP_ID_PREFIX_105
            if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.105") {

                # It's structured the same way as the METAEKUS, just with
                # different OIDs (always the same)
                my $Thing =
                  $asn_ekus->decode($MD->{'MetaDataValue'}->{'RealContent'});
                foreach my $oid (@$Thing) {
                    $oid =~ s/1\.3\.6\.1\.4\.1\.311/OID-Microsoft/;
                }
                $MD->{'PropID105'} = $Thing;
                delete $MD->{'MetaDataType'};
                delete $MD->{'MetaDataValue'};
            }
        }
    }

    # Pretty print the result as a JSON stuff
    print to_json($ctl, { pretty => 1 });
}
