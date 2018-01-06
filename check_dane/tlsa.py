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



class TLSARecord:
    """Class representing a TLSA record"""
    def __init__(self, usage, selector, matching, payload):
        self._usage = usage
        self._selector = selector
        self._matching = matching
        self._payload = payload


    def match(self, certificate):
        """Returns true if the certificate is covered by this TLSA record"""
        if self._selector == 0:
            verifieddata = certificate
        elif self._selector == 1:
            verifieddata = get_spki(certificate)
        else:
            # currently only 0 and 1 are assigned
            sys.stderr.write("Only selectors 0 and 1 supported\n")

        if self._matching == 0:
            if verifieddata == self._payload:
                return True

        elif self._matching == 1:
            if hashlib.sha256(verifieddata).digest() == self._payload:
                return True

        elif self._matching == 2:
            if hashlib.sha512(verifieddata).digest() == self._payload:
                return True

        else:
            # currently only 0, 1 and 2 are assigned
            logging.warning("Only matching types 0, 1 and 2 supported\n")

        return False



    @property
    def usage(self):
        """Usage for this TLSA record"""
        return self._usage


    @property
    def selector(self):
        """Selector for this record"""
        return self._selector


    @property
    def matching(self):
        """Way to match data against certificate"""
        return self._matching


    @property
    def payload(self):
        """Payload data of the TLSA record"""
        return self._payload


    def __repr__(self):
        hexencoder = codecs.getencoder('hex')
        return '<TLSA %d %d %d %s>' % (self._usage, self._selector, self._matching, hexencoder(self._payload)[0].decode())



def get_tlsa_records(resolver, name):
    """Extracts all TLSA records for a given name"""

    logging.debug("searching for TLSA record on %s", name)
    s, r = resolver.resolve(name, rrtype=RR_TYPE_TLSA)
    if 0 != s:
        ub_strerror(s)
        return

    if r.data is None:
        logging.warning("No TLSA record returned")
        return set()

    result = set()
    for record in r.data.data:
        usage = record[0]
        selector = record[1]
        matching = record[2]
        data = record[3:]
        result.add(TLSARecord(usage, selector, matching, data))
        
    return result


def match_tlsa_records(records, certificates):
    """Returns all TLSA records matching the certificate"""

    usedrecords = set()
    result = 0

    for certificate in certificates:
        recfound = False

        for record in records:
            if record.match(certificate):
                logging.info("Matched record %s", record)
                usedrecords.add(record)
                recfound = True

        if not recfound:
            logging.error("No TLSA record returned")
            result = 2

    for record in records:
        if not record in usedrecords:
            logging.warning("Unused record %s", record)
            if result == 0:
                result = 1

    return result


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
        usage = ord(record[0])
        selector = ord(record[1])
        matching = ord(record[2])
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
