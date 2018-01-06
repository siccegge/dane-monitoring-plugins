#!/usr/bin/python3

#!/usr/bin/python3

from __future__ import print_function

import argparse
import logging

from ssl import SSLContext, PROTOCOL_TLSv1_2, CERT_REQUIRED
from socket import socket

from check_dane.cert import add_certificate_options
from check_dane.abstract import DaneChecker


class SmtpDaneChecker(DaneChecker):
    def _init_connection(self, family, host, port):

        if self.ssl:
            connection = self._sslcontext.wrap_socket(socket(family),
                                                      server_hostname=host)
            connection.connect((host, port))
            answer = connection.recv(512)
            logging.debug(answer)

            connection.send(b"EHLO localhost\r\n")
            answer = connection.recv(512)
            logging.debug(answer)

        else:
            connection = socket(family=family)
            connection.connect((host, port))
            answer = connection.recv(512)
            logging.debug(answer)

            connection.send(b"EHLO localhost\r\n")
            answer = connection.recv(512)
            logging.debug(answer)

            connection.send(b"STARTTLS\r\n")
            answer = connection.recv(512)
            logging.debug(answer)

            connection = self._sslcontext.wrap_socket(connection, server_hostname=host)
            connection.do_handshake()

            connection.send(b"EHLO localhost\r\n")
            answer = connection.recv(512)
            logging.debug(answer)

        return connection


    @property
    def port(self):
        return self._port


    @property
    def ssl(self):
        return self._ssl


    def _close_connection(self, connection):
        connection.send(b"QUIT\r\n")
        answer = connection.recv(512)
        logging.debug(answer)
        connection.close()


    def __init__(self):
        self._port = None
        self._ssl = None
        DaneChecker.__init__(self)


    def set_args(self, args):
        DaneChecker.set_args(self, args)

        self._ssl = args.ssl
        if args.port == 0:
            self._port = 465 if args.ssl else 25
        else:
            self._port = args.port

        sslcontext = SSLContext(PROTOCOL_TLSv1_2)
        sslcontext.verify_mode = CERT_REQUIRED
        sslcontext.load_verify_locations(args.castore)

        self._sslcontext = sslcontext


    def generate_menu(self, argparser):
        DaneChecker.generate_menu(self, argparser)
        argparser.add_argument("-p", "--port",
                               action="store", type=int, default=0,
                               help="SMTP port")
        argparser.add_argument("--ssl",
                               action="store_true",
                               help="Use direct TLS connection instead of starttls (default: disabled)")





def main():
    logging.basicConfig(format='%(levelname)5s %(message)s')
    checker = SmtpDaneChecker()
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
