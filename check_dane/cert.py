#!/usr/bin/python3

from datetime import datetime
import logging
from ssl import cert_time_to_seconds

from pyasn1_modules import rfc2459
from pyasn1.codec.der import decoder, encoder

def verify_certificate(cert, args):
    expiretimestamp = cert_time_to_seconds(cert['notAfter'])
    starttimestamp = cert_time_to_seconds(cert['notBefore'])

    if datetime.utcfromtimestamp(starttimestamp) > datetime.utcnow():
        logging.error("Certificate will only be valid starting %s", cert['notBefore'])
        return 2

    if datetime.utcfromtimestamp(expiretimestamp) < datetime.utcnow():
        logging.error("Certificate will only be valid until %s", cert['notAfter'])
        return 2

    delta = datetime.utcfromtimestamp(expiretimestamp) - datetime.utcnow()
    deltastr = str(delta).split(",")

    if delta.days < args.critdays:
        logging.error("expires in %8s,%16s", deltastr[0], deltastr[1])
        return 2
    elif delta.days < args.warndays:
        logging.warn("expires in %8s,%16s", deltastr[0], deltastr[1])
        return 1

    return 0

def get_spki(certificate):
    cert = decoder.decode(certificate, asn1Spec=rfc2459.Certificate())[0]
    spki = cert['tbsCertificate']["subjectPublicKeyInfo"]
    return encoder.encode(spki)

def add_certificate_options(argparser):
    argparser.add_argument("--warndays", type=int, default=-1,
                           help="Days before certificate expiration to warn")
    argparser.add_argument("--critdays", type=int, default=-1,
                           help="Days before certificate expiration to raise error")
