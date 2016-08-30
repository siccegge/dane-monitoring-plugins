#!/usr/bin/python3

import struct
import logging
from datetime import datetime

from unbound import ub_ctx, ub_strerror
from unbound import RR_TYPE_A, RR_TYPE_AAAA, RR_TYPE_RRSIG

from ldns import ldns_wire2pkt
from ldns import LDNS_SECTION_ANSWER


def _parse_rrsig_date(expirestring):
    expires = datetime(int(expirestring[:4]),
                       int(expirestring[4:6]),
                       int(expirestring[6:8]),
                       int(expirestring[8:10]),
                       int(expirestring[10:12]),
                       int(expirestring[12:14]))
    return expires


def format_address(data, datatype):
    """Given a answer packet for an A or AAAA query, return the string
       representation of the address
    """
    if datatype == RR_TYPE_A:
        return '.'.join([str(a) for a in data])
    elif datatype == RR_TYPE_AAAA:
        data = list(struct.iter_unpack("!H", data))
        return ":".join(["%x" % a for a in data])
    else:
        return None


def dnssec_verify_rrsig_validity(data, warn=-1, critical=0):
    """Given a answer packet confirm validity of rrsigs (with safety) """
    now = datetime.utcnow()

    s, packet = ldns_wire2pkt(data)
    if s != 0:
        logging.error("Parsing packet failed with errorcode %d", s)
        return 2

    rrsigs = packet.rr_list_by_type(RR_TYPE_RRSIG, LDNS_SECTION_ANSWER).rrs()
    rrsig = next(rrsigs)

    expire = _parse_rrsig_date(str(rrsig.rrsig_expiration()))
    incept = _parse_rrsig_date(str(rrsig.rrsig_inception()))

    if now < incept:
        logging.error("Signature not yet valid, only from %s", incept)
        return 2

    stillvalid = expire - now
    deltastr = str(stillvalid).split(",")

    if stillvalid.days < max(0, critical):
        logging.error("expires in %8s,%16s", deltastr[0], deltastr[1])
        return 2
    elif stillvalid.days < warn:
        logging.warning("expires in %8s,%16s", deltastr[0], deltastr[1])
        return 1


class ResolverException(BaseException):
    def __init__(self, message):
        BaseException.__init__(self)
        self.message = message


class Resolver:
    def __init__(self, ancor, fwd=None):
        self._resolver = ub_ctx()
        status = self._resolver.add_ta_file(ancor)
        if status != 0:
            raise ResolverException(ub_strerror(status))

        if fwd is not None:
            status = self._resolver.set_fwd(fwd)
            if status != 0:
                raise ResolverException(ub_strerror(status))


    def resolve(self, name, rrtype, secure=False):
        status, result = self._resolver.resolve(name, rrtype)
        if 0 != status:
            raise ResolverException(ub_strerror(status))

        if secure and not result.secure:
            raise ResolverException("Response was not signed")

        return result
