from abc import ABCMeta, abstractmethod
from unbound import ub_ctx
from socket import socket, AF_INET6, AF_INET
from ssl import SSLContext, PROTOCOL_TLSv1_2, CERT_REQUIRED


from check_dane.cert import verify_certificate, add_certificate_options
from check_dane.tlsa import get_tlsa_records, match_tlsa_records


class DaneWarning:
    pass

class DaneError:
    pass


class DaneChecker:
    def __init__(self):
        pass


    @abstractmethod
    def _init_connection(self):
        pass


    @abstractmethod
    def _close_connection(self):
        pass


    @property
    @abstractmethod
    def port(self):
        pass

    
    def _gather_certificates(self):
        retval = 0
        certificates = set()
        for afamily in self._afamilies:
            try:
                connection = self._init_connection(afamily, self._host, self.port)
            except ConnectionRefusedError:
                logging.error("Connection refused")
                return 2

            nretval = verify_certificate(connection.getpeercert(), self._args)
            retval = max(retval, nretval)
            certificates.add(connection.getpeercert(binary_form=True))

            self._close_connection(connection)

        return certificates
    
    
    def _gather_records(self):
        return get_tlsa_records(self._resolver, "_%d._tcp.%s" % (self.port, self._host))

        
    def generate_menu(self, argparser):
        argparser.add_argument("Host")

        argparser.add_argument("--check-dane",
                            action="store_false",
                            help="Verify presented certificate via DANE (default: enabled)")
        argparser.add_argument("--check-ca",
                            action="store_false",
                            help="Verify presented certificate via the CA system (default: enabled)")
        argparser.add_argument("--check-expire",
                            action="store_false",
                            help="Verify presented certificate for expiration (default: enabled)")

        argparser.add_argument("-a", "--ancor",
                            action="store", type=str, default="/usr/share/dns/root.key",
                            help="DNSSEC root ancor")
        argparser.add_argument("--castore", action="store", type=str,
                            default="/etc/ssl/certs/ca-certificates.crt",
                            help="ca certificate bundle")

        group = argparser.add_mutually_exclusive_group()
        group.add_argument("-6", "--6", action="store_true", dest="use6", help="check via IPv6 only")
        group.add_argument("-4", "--4", action="store_true", dest="use4", help="check via IPv4 only")


    def set_args(self, args):        
        self._args = args
        resolver = ub_ctx()
        resolver.add_ta_file(args.ancor)
        self._resolver = resolver

        if args.use6:
            self._afamilies = [AF_INET6]
        elif args.use4:
            self._afamilies = [AF_INET]
        else:
            self._afamilies = [AF_INET, AF_INET6]

        self._host = args.Host.encode('idna').decode()
        

    def check(self):
        records = self._gather_records()
        certificates = self._gather_certificates()
        return match_tlsa_records(records, certificates)
