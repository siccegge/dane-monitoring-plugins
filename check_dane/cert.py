#!/usr/bin/python3

from pyasn1_modules import rfc2459
from pyasn1.codec.der import decoder, encoder


def get_spki(certificate):
    cert = decoder.decode(certificate, asn1Spec=rfc2459.Certificate())[0]
    spki = cert['tbsCertificate']["subjectPublicKeyInfo"]
    return encoder.encode(spki)
