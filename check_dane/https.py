#!/usr/bin/python3

from __future__ import print_function

import argparse
import logging

from ssl import SSLContext, PROTOCOL_TLSv1_2, CERT_REQUIRED
from socket import socket

from check_dane.cert import add_certificate_options
from check_dane.abstract import DaneChecker


class HttpsDaneChecker(DaneChecker):
    def _init_connection(self, family, host, port):
        connection = self._sslcontext.wrap_socket(socket(family),
                                                  server_hostname=host)
        connection.connect((host, port))
        connection.send(b"HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())
        answer = connection.recv(512)
        logging.debug(answer)

        return connection


    @property
    def port(self):
        return self._port


    def _close_connection(self, connection):
        connection.close()


    def __init__(self):
        DaneChecker.__init__(self)


    def set_args(self, args):
        DaneChecker.set_args(self, args)

        self._port = args.port

        sslcontext = SSLContext(PROTOCOL_TLSv1_2)
        sslcontext.verify_mode = CERT_REQUIRED
        sslcontext.load_verify_locations(args.castore)

        self._sslcontext = sslcontext


    def generate_menu(self, argparser):
        DaneChecker.generate_menu(self, argparser)
        argparser.add_argument("-p", "--port",
                               action="store", type=int, default=443,
                               help="HTTPS port")




def main():
    logging.basicConfig(format='%(levelname)5s %(message)s')
    checker = HttpsDaneChecker()
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
