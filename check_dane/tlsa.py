#!/usr/bin/python3

import sys
import codecs
import hashlib

from .cert import get_spki

from unbound import RR_TYPE_A, RR_TYPE_AAAA
from unbound import idn2dname, ub_strerror

def verify_tlsa_record(resolver, record, certificate):
    print(record)
    print(hashlib.sha256(certificate).hexdigest())
    s, r = resolver.resolve(record, rrtype=52)
    if 0 != s:
        ub_strerror(s)
        return

    for record in r.data.data:
        hexencoder = codecs.getencoder('hex')
        usage = record[0]
        selector = record[1]
        matching = record[2]
        data = record[3:]

        if usage != 3:
            sys.stderr.write("Only 'Domain-issued certificate' records supported\n")

        if selector == 0:
            verifieddata = certificate
        elif selector == 1:
            verifieddata = get_spki(certificate)
        else:
            # currently only 0 and 1 are assigned
            sys.stderr.write("Only selectors 0 and 1 supported\n")

        if matching == 0:
            if verifieddata == data:
                print("success")
                return 0
        elif matching == 1:
            if hashlib.sha256(verifieddata).digest() == data:
                print("success")
                return 0
        elif matching == 2:
            if hashlib.sha512(verifieddata).digest() == data:
                print("success")
                return 0
        else:
            # currently only 0, 1 and 2 are assigned
            sys.stderr.write("Only matching types 0, 1 and 2 supported\n")

    sys.stderr.write("could not verify any tlsa record\n")
    return -1
