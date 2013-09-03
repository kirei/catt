# Certification Authority Trust Tracker


## Primary Sources

### Apple

Root certificates extracted using **extract-osx-trust.sh** and and split into
files using **split-bundle.pl**. EV OIDs extracted using **extract-osx-ev-pl**.

More information:

- http://www.apple.com/certificateauthority/ca_program.html

- Root CA: /System/Library/Keychains/SystemRootCertificates.keychain
- EV status: /System/Library/Keychains/EVRoots.plist

### Mozilla NSS

Root certificates fetched using **mk-ca-bundle.pl** and split into files using
**split-bundle.pl**. EV OIDs extracted using **extract-mozilla-ev.py**.

More information:

- Root CA: http://mxr.mozilla.org/mozilla-central/source/security/nss/lib/ckfw/builtins/certdata.txt
- EV status: https://mxr.mozilla.org/mozilla-central/source/security/manager/ssl/src/nsIdentityChecking.cpp

### Microsoft

A snapshot of trusted root certificates can be found in
**xfiles/microsoft-2012-12.xlsx**. No tool for extraction yet available.

More information:

- http://social.technet.microsoft.com/wiki/contents/articles/3281.introduction-to-the-microsoft-root-certificate-program.aspx
- http://social.technet.microsoft.com/wiki/contents/articles/14215.windows-and-windows-phone-8-ssl-root-certificate-program-member-cas.aspx

### Opera

No tool for extraction not yet available.

More information:

- http://www.opera.com/docs/ca/

### Oracle Java

Root certificates extracted from the Java keystore using
**extract-java-trust.pl**.

More information:

- http://www.oracle.com/technetwork/java/javase/javasecarootcertsprogram-1876540.html


## Secondary Sources

### Google Chrome

Chrome trusts root certificates included by the underlying operating system:

- Microsoft: see above
- Apple OS X: see above
- Linux: NSS
- Android: NSS, see below

More information:

- http://www.chromium.org/Home/chromium-security/root-ca-policy
- http://src.chromium.org/viewvc/chrome/trunk/src/net/cert/ev_root_ca_metadata.cc

### Google ChromeOS

All root certificates pulled from NSS.

### Google Android

All root certificates mostly pulled from NSS, although this may be changed by
devices manufacturers or carriers.

- https://android.googlesource.com/platform/libcore/+/master/CaCerts.mk
- https://android.googlesource.com/platform/libcore/+/master/luni/src/main/files
- https://android.googlesource.com/platform/libcore/+/master/luni/src/main/files/cacerts/
- http://www.andreabaccega.com/blog/2010/09/23/android-root-certification-authorities-list/



## Publishing Trusted Root Certificates

We urge root certificate program managers to publish the following information:

- All currently approved and trusted root certificates. The preferred
  publishing format is X.509 certificates encoded as PEM or DER, but other
  formats may be usable as well (e.g., Mozilla certdata as mentioned above).
  Note that publishing certificate fingerprints is not enough - we do need the
  actual certificate.

- All currently approved and trusted Extended Validation OIDs together with
  each corresponding issuing CA fingerprint.

We strongly recommend that the data above is published at a stable long-term
URL, in order to be able to fetch the data automatically.
