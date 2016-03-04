#!/bin/python2

import binascii
import lxml.etree
import os
import pdfrw
import subprocess
import sys
import zlib

# Note: The PDF signatures on this document will not be checked by this script
ATTACHMENT_NAME = ("(\xfe\xff\0S\0e\0c\0u\0r\0i\0t\0y\0S\0e\0t\0t\0i\0n\0g\0s"
                   "\0.\0x\0m\0l)")
HEADER = "-----BEGIN CERTIFICATE-----"
FOOTER = "-----END CERTIFICATE-----"

SIGNATURE_FILE_NAME = "signature.der"
MESSAGE_FILE_NAME = "message.bin"


def base64_to_pem(value):
    chunks = [value[i:i + 64] for i in range(0, len(value), 64)]
    lines = [HEADER] + chunks + [FOOTER]
    return "\n".join(lines)


def verify_signature(reader, filename):
    signature = reader["/Root"]["/Perms"][pdfrw.PdfName("DocMDP")]
    if (signature["/Filter"] != "/Adobe.PPKLite" or
            signature["/SubFilter"] != "/adbe.pkcs7.detached"):
        raise NotImplementedError("Unsupported signature type")

    signature_string = signature["/Contents"]
    signature_hex = signature_string.replace("<", "").replace(">", "")
    signature_raw = binascii.unhexlify(signature_hex)  # DER-encoded PKCS-7 sig

    pdf_file = open(filename, "rb")
    pdf_data = pdf_file.read()
    pdf_file.close()

    signature_offset = pdf_data.index(signature_string)
    signature_end = signature_offset + len(signature_string)
    byte_range = [0, signature_offset, signature_end,
                  len(pdf_data) - signature_end]
    for i in range(4):
        if int(signature["/ByteRange"][i]) != byte_range[i]:
            raise Exception("Byte range did not match expected position")

    script_dir = os.path.dirname(os.path.realpath(__file__))
    adobe_root = os.path.join(script_dir, "..", "xfiles", "adoberoot.pem")

    signature_file = message_file = None
    try:
        signature_file = open(SIGNATURE_FILE_NAME, "wb")
        signature_file.write(signature_raw)
        signature_file.close()
        signature_file = None
        try:
            message_file = open(MESSAGE_FILE_NAME, "wb")
            message_file.write(pdf_data[:signature_offset])
            message_file.write(pdf_data[signature_end:])
            message_file.close()
            message_file = None

            process = subprocess.Popen(["openssl", "smime", "-verify",
                                        "-in", SIGNATURE_FILE_NAME,
                                        "-inform", "der",
                                        "-content", MESSAGE_FILE_NAME,
                                        "-CAfile", adobe_root,
                                        "-purpose", "any",
                                        "-out", "/dev/null"],
                                       stderr=subprocess.PIPE)
            text = process.communicate()[1]
            if process.returncode != 0 or text != "Verification successful\n":
                raise Exception("Signature verification failed:\n%s" % text)

        finally:
            if message_file:
                message_file.close()
            if os.path.isfile(MESSAGE_FILE_NAME):
                os.unlink(MESSAGE_FILE_NAME)
    finally:
        if signature_file:
            signature_file.close()
        if os.path.isfile(SIGNATURE_FILE_NAME):
            os.unlink(SIGNATURE_FILE_NAME)


def main(filename):
    reader = pdfrw.PdfReader(filename)
    verify_signature(reader, filename)

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
        process = subprocess.Popen(["openssl",
                                    "x509",
                                    "-noout",
                                    "-fingerprint"],
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE)
        fingerprint = process.communicate(input=cert_pem)[0]
        if process.returncode != 0:
            raise subprocess.CalledProcessError()

        fingerprint = fingerprint.replace("SHA1 Fingerprint=", "")
        fingerprint = fingerprint.replace(":", "")
        fingerprint = fingerprint.strip()

        f = open(fingerprint + ".pem", "w")
        f.write(cert_pem)
        f.close()


if __name__ == "__main__":
    if len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        print >> sys.stderr, ("Usage: python2 extract-adobe-aatl.py "
                              "<filename.acrobatsecuritysettings>")
