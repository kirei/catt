#!/bin/python2

from M2Crypto import X509
import lxml.etree
import pdfrw
import sys
import zlib

# Note: The PDF signatures on this document will not be checked by this script
ATTACHMENT_NAME = ("(\xfe\xff\0S\0e\0c\0u\0r\0i\0t\0y\0S\0e\0t\0t\0i\0n\0g\0s"
                   "\0.\0x\0m\0l)")
HEADER = "-----BEGIN CERTIFICATE-----"
FOOTER = "-----END CERTIFICATE-----"


def base64_to_pem(value):
    chunks = [value[i:i + 64] for i in range(0, len(value), 64)]
    lines = [HEADER] + chunks + [FOOTER]
    return "\n".join(lines)


def main(filename):
    reader = pdfrw.PdfReader(filename)
    embedded_files = reader["/Root"]["/Names"]["/EmbeddedFiles"]
    if embedded_files["/Names"][0] != ATTACHMENT_NAME:
        raise Exception("Unexpected attachment name %s" %
                        embedded_files["/Names"][0])

    file_spec = embedded_files["/Names"][1]
    embedded_file = file_spec["/EF"][pdfrw.PdfName("F")]
    if embedded_file["/Filter"] != "/FlateDecode":
        raise NotImplementedError("Unsupported compression algorithm %s" %
                                  embedded_file["/Filter"])

    xml = zlib.decompress(embedded_file.stream)
    doc = lxml.etree.fromstring(xml)
    trusted_identities = doc[0]
    for identity in trusted_identities:
        import_action = identity.xpath("ImportAction/text()")[0]
        source = identity.xpath("Identification/Source/text()")[0]
        if import_action not in ("1", "2", "3"):  # what is the difference?
            raise Exception("Unrecognized ImportAction %s" % import_action)
        if source != "AATL":
            raise Exception("Unrecognized source %s" % import_action)

        cert_pem = base64_to_pem(identity.xpath("Certificate/text()")[0])
        x509 = X509.load_cert_string(cert_pem, X509.FORMAT_PEM)
        fingerprint = x509.get_fingerprint("sha1")
        subject = x509.get_subject()

        print >> sys.stderr, "Exporting %s" % subject
        f = open(fingerprint + ".pem", "w")
        f.write(cert_pem)
        f.close()


if __name__ == "__main__":
    if len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        print >> sys.stderr, ("Usage: python2 extract-adobe-aatl.py "
                              "<filename.acrobatsecuritysettings>")
