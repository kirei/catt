# Certification Authority Trust Tracker

## TA Sources

### Apple

- http://www.apple.com/certificateauthority/ca_program.html
- TA extracted using extract-osx-trust.sh
  
### Microsoft
 
- http://social.technet.microsoft.com/wiki/contents/articles/3281.introduction-to-the-microsoft-root-certificate-program.aspx
- http://social.technet.microsoft.com/wiki/contents/articles/14215.windows-and-windows-phone-8-ssl-root-certificate-program-member-cas.aspx
 
### Mozilla NSS

- http://mxr.mozilla.org/mozilla-central/source/security/nss/lib/ckfw/builtins/certdata.txt
- TA extracted using mk-ca-bundle.pl

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
