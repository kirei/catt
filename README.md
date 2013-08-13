# Certification Authority Trust Tracker

## TA Sources

### Apple

- TA extracted using extract-osx-trust.sh
- EV OIDs extracted using extract-osx-ev.pl

- http://www.apple.com/certificateauthority/ca_program.html
- Root CA: /System/Library/Keychains/SystemRootCertificates.keychain
- EV status: /System/Library/Keychains/EVRoots.plist

### Microsoft
 
- http://social.technet.microsoft.com/wiki/contents/articles/3281.introduction-to-the-microsoft-root-certificate-program.aspx
- http://social.technet.microsoft.com/wiki/contents/articles/14215.windows-and-windows-phone-8-ssl-root-certificate-program-member-cas.aspx
 
### Mozilla NSS

- TA extracted using mk-ca-bundle.pl
- EV OIDs extracted using extract_mozilla_ev_data.py

- http://mxr.mozilla.org/mozilla-central/source/security/nss/lib/ckfw/builtins/certdata.txt
- EV status: https://mxr.mozilla.org/mozilla-central/source/security/manager/ssl/src/nsIdentityChecking.cpp


### Opera

- http://www.opera.com/docs/ca/

(will transition to NSS)


### Google Chrome

- http://www.chromium.org/Home/chromium-security/root-ca-policy
- http://src.chromium.org/viewvc/chrome/trunk/src/net/cert/ev_root_ca_metadata.cc

### Google ChromeOS

- Pulled from NSS

### Google Android

- https://android.googlesource.com/platform/libcore/+/master/CaCerts.mk
- https://android.googlesource.com/platform/libcore/+/master/luni/src/main/files
- https://android.googlesource.com/platform/libcore/+/master/luni/src/main/files/cacerts/


- http://www.andreabaccega.com/blog/2010/09/23/android-root-certification-authorities-list/
