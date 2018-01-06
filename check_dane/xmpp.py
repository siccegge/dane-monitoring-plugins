#!/usr/bin/python3

#!/usr/bin/python3

from __future__ import print_function

import argparse
import logging

from ssl import SSLContext, PROTOCOL_TLSv1_2, CERT_REQUIRED
from socket import socket

from check_dane.tlsa import get_tlsa_records
from check_dane.cert import add_certificate_options
from check_dane.abstract import DaneChecker
from check_dane.resolve import Resolver, srv_lookup

XMPP_OPEN = ("<stream:stream xmlns='jabber:{0}' xmlns:stream='"
             "http://etherx.jabber.org/streams' xmlns:tls='http://www.ietf.org/rfc/"
             "rfc2595.txt' to='{1}' xml:lang='en' version='1.0'>")
XMPP_CLOSE = "</stream:stream>"
XMPP_STARTTLS = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"

class XmppDaneChecker(DaneChecker):
    def _init_connection(self, family, host, port):

        logging.debug("Connecting to %s:%d", host, port)

        connection = socket(family=family)
        connection.connect((host, port))

        connection.sendall(XMPP_OPEN.format(self.servicetype, self._hostname).encode())
        answer = connection.recv(4096)
        logging.debug(answer)

        if not b'</stream:features>' in answer:
            answer = connection.recv(4096)
            logging.debug(answer)

        connection.sendall(XMPP_STARTTLS.encode())
        answer = connection.recv(4096)
        logging.debug(answer)

        print(host, self._hostname)
        connection = self._sslcontext.wrap_socket(connection, server_hostname=self._hostname)
        connection.do_handshake()

        connection.sendall(XMPP_OPEN.format(self.servicetype, self._hostname).encode())
        answer = connection.recv(4096)
        logging.debug(answer)

        if not b'</stream:features>' in answer:
            answer = connection.recv(4096)
            logging.debug(answer)

        return connection


    @property
    def port(self):
        return self._port


    @property
    def servicetype(self):
        return self._type


    def _gather_certificates(self):
        result = set()
        for (host, port), meta in self._endpoints:
            self._host = host
            self._port = port
            self._type = meta['type']
            result.update(DaneChecker._gather_certificates(self))

        return result


    def _gather_records(self):
        result = set()
        for (host, port), _ in self._endpoints:
            print(repr((host, port)))
            result.update(get_tlsa_records(self._resolver, "_%d._tcp.%s" % (port, host)))

        return result


    def _close_connection(self, connection):
        connection.send(XMPP_CLOSE.encode())
        answer = connection.recv(512)
        logging.debug(answer)
        connection.close()


    def __init__(self):
        self._port = None
        self._ssl = None
        self._host = None
        self._hostname = None
        DaneChecker.__init__(self)


    def set_args(self, args):
        DaneChecker.set_args(self, args)

        sslcontext = SSLContext(PROTOCOL_TLSv1_2)
        sslcontext.verify_mode = CERT_REQUIRED
        sslcontext.load_verify_locations(args.castore)

        cresolver = Resolver(args.ancor)
        self._sslcontext = sslcontext

        self._hostname = args.Host.encode('idna').decode()
        endpoints = []
        if not args.s2s:
            for endpoint, meta in srv_lookup("_xmpp-client._tcp.%s" %
                                             self._hostname,
                                             cresolver):
                meta['type'] = 'client'
                endpoints.append((endpoint, meta))
        if not args.c2s:
            for endpoint, meta in srv_lookup("_xmpp-server._tcp.%s" %
                                             self._hostname,
                                             cresolver):
                meta['type'] = 'server'
                endpoints.append((endpoint, meta))

        self._endpoints = endpoints


    def generate_menu(self, argparser):
        DaneChecker.generate_menu(self, argparser)
        group = argparser.add_mutually_exclusive_group()
        group.add_argument("--s2s", action="store_true",
                           help="Only check server-to-server connections")
        group.add_argument("--c2s", action="store_true",
                           help="Only check client-to-server connections")
        argparser.add_argument("-p", "--port",
                               action="store", type=int, default=0,
                               help="SMTP port")




def main():
    logging.basicConfig(format='%(levelname)5s %(message)s')
    checker = XmppDaneChecker()
    parser = argparse.ArgumentParser()

    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--quiet", action="store_true")

    checker.generate_menu(parser)
    add_certificate_options(parser)

    args = parser.parse_args()
    checker.set_args(args)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    else:
        logging.getLogger().setLevel(logging.INFO)

    return checker.check()


if __name__ == '__main__':
    import sys
    sys.exit(main())
