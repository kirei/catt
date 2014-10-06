# Certification Authority Trust Tracker

## What is CATT?

CATT (_Certification Authority Trust Tracker_) is a collection of scripts and
data to track which certification authorities are trusted by various root CA
programs.


## Publishing Trusted Root Certificates

The CATT project urge root certificate program managers to publish the
following information:

- All currently approved and trusted root certificates. The preferred
  publishing format is X.509 certificates encoded as PEM or DER, but other
  formats may be usable as well (e.g., Mozilla certdata as mentioned above).
  Note that publishing certificate fingerprints is not enough - we do need the
  actual certificate.

- All currently approved and trusted Extended Validation OIDs together with
  each corresponding issuing CA fingerprint.

We strongly recommend that the data above is published at a stable long-term
URL, in order to be able to fetch the data automatically.


##  Trust Sources

### Apple

- http://www.apple.com/certificateauthority/ca_program.html

Root certificates extracted using **extract-osx-trust.sh** and and split into
files using **split-bundle.pl**. EV OIDs extracted using **extract-osx-ev-pl**.

- Root CA: /System/Library/Keychains/SystemRootCertificates.keychain
- EV status: /System/Library/Keychains/EVRoots.plist

Apple publish a [list of trusted root certificates for iOS](http://support.apple.com/kb/ht5012), but as this list does not include full certificate data (including public keys) it cannot be used by CATT.


### Mozilla

- https://www.mozilla.org/projects/security/certs/policy/

Root certificates fetched using **mk-ca-bundle.pl** and split into files using
**split-bundle.pl**. EV OIDs extracted using **extract-mozilla-ev.py**.

More information:

- Root CA: http://mxr.mozilla.org/mozilla-central/source/security/nss/lib/ckfw/builtins/certdata.txt
- EV status: https://mxr.mozilla.org/mozilla-central/source/security/manager/ssl/src/nsIdentityChecking.cpp

### Microsoft

- http://technet.microsoft.com/en-us/library/cc751157.aspx
- https://support.microsoft.com/kb/2677070

Root certificate metadata is fetched using **fetch-microsoft-authroot.sh**,
producing a JSON file called **authroot.json**. Actual root certificates
fetched using the contents of the JSON file by **fetch-microsoft-certs.sh**. EV
OIDs are not yet extracted.

A ancient snapshot of trusted root certificates can also be found in
**xfiles/microsoft-2012-12.xlsx**.

- http://social.technet.microsoft.com/wiki/contents/articles/3281.introduction-to-the-microsoft-root-certificate-program.aspx
- http://social.technet.microsoft.com/wiki/contents/articles/14215.windows-and-windows-phone-8-ssl-root-certificate-program-member-cas.aspx


### Oracle Java SE

- http://www.oracle.com/technetwork/java/javase/javasecarootcertsprogram-1876540.html

Root certificates extracted from the Java keystore using
**extract-java-trust.pl**.
