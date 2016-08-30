#!/usr/bin/python3

import sys
import codecs
import hashlib
import logging

from .cert import get_spki

from unbound import ub_strerror

try:
    from unbound import RR_TYPE_TLSA
except ImportError:
    RR_TYPE_TLSA = 52

def verify_tlsa_record(resolver, record, certificate):
    logging.debug("searching for TLSA record on %s", record)
    s, r = resolver.resolve(record, rrtype=RR_TYPE_TLSA)
    if 0 != s:
        ub_strerror(s)
        return

    if r.data is None:
        logging.error("No TLSA record returned")
        return 2

    for record in r.data.data:
        hexencoder = codecs.getencoder('hex')
        usage = record[0]
        selector = record[1]
        matching = record[2]
        data = record[3:]

        if usage != 3:
            logging.warning("Only 'Domain-issued certificate' records supported\n")

        if selector == 0:
            verifieddata = certificate
        elif selector == 1:
            verifieddata = get_spki(certificate)
        else:
            # currently only 0 and 1 are assigned
            sys.stderr.write("Only selectors 0 and 1 supported\n")

        if matching == 0:
            if verifieddata == data:
                logging.info("Found matching record: `TLSA %d %d %d %s`",
                             usage, selector, matching, hexencoder(data)[0])
                return 0
        elif matching == 1:
            if hashlib.sha256(verifieddata).digest() == data:
                logging.info("Found matching record: `TLSA %d %d %d %s`",
                             usage, selector, matching, hexencoder(data)[0].decode())
                return 0
        elif matching == 2:
            if hashlib.sha512(verifieddata).digest() == data:
                logging.info("Found matching record: `TLSA %d %d %d %s`",
                             usage, selector, matching, hexencoder(data)[0].decode())
                return 0
        else:
            # currently only 0, 1 and 2 are assigned
            logging.warning("Only matching types 0, 1 and 2 supported\n")

    logging.error("could not verify any tlsa record\n")
    return 2
