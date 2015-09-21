Instructions on how to generate trust stores that can be used in SSLyze.


### Microsoft

    brew install cabextract
    sudo cpan install JSON

    ./fetch-microsoft-authroot.sh
    ./fetch-microsoft-certs.sh

The certificates will then be available in microsoft.pem.


### Apple OS X

You need to be on an OS X host, then run:

    sudo cpan Mac::PropertyList
   ./update-osx.sh

The certificates will then be available in apple.pem.


### Mozilla

  ./mk-ca-bundle.pl

The certificates will then be available in ca-bundles.crt.


### Java

You need to be on an OS X host, then run:

  ./extract-java-trust.pl

The certificates will then be available in java.pem.

### Google

https://pki.google.com/roots.pem
