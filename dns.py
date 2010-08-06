# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.

# TorDNSEL-compatible DNS implementation using Twisted Names
# and the TorBEL query interface.
import sys

from zope.interface import implements
from twisted.names import server, dns, common, error
from twisted.internet import reactor, interfaces, defer
from twisted.python import failure

from torbel.query import ExitList
from torbel import logger
from ipaddr import IPAddress
log = logger.create_logger("tordnsel", logger.DEBUG)

class TorResolver(common.ResolverBase):
    """ TwistedNames resolver based on torbel.query. """
    implements(interfaces.IResolver)

    def __init__(self, root, filename):
        common.ResolverBase.__init__(self)
        self.el = ExitList(filename)
        self.root = root

    def _lookup(self, name, cls, type, timeout):
        def nxdomain(name):
            return defer.fail(failure.Failure(error.DomainError(name)))

        def refused(name):
            return defer.fail(failure.Failure(error.DNSQueryRefusedError(name)))

        # Refuse non-IN/A questions.
        if cls != dns.IN or type != dns.A:
            log.debug("We don't handle cls %s type %s", cls, type)
            return refused(name)
        # Refuse requests for requests that aren't in our zone of authority.
        if not name.endswith(self.root):
            log.debug("We are authoritative and don't handle the TLD of %s",
                      repr(name))
            return refused(name)
        
        q = name.split(".")
        if len(q) < 10 + len(self.root.split(".")):
            return nxdomain(name)

        # Attempt to parse the DNSEL request.
        try:
            tor_ip = IPAddress("%s.%s.%s.%s" % (q[3], q[2], q[1], q[0]))
            dest_port = int(q[4])
            dest_ip = IPAddress("%s.%s.%s.%s" % (q[8], q[7], q[6], q[5]))
            qtype = q[9]
        # Otherwise barf back NXDOMAIN.
        except:
            return nxdomain(name)

        log.debug("Query %s = %s to %s:%d?", name, tor_ip, dest_ip, dest_port)

        router = self.el.is_tor_traffic(int(tor_ip), dest_port)
        if router:
            log.debug("Request for %s:%d matches router %s(%s).",
                      tor_ip, dest_port, router.idhex, router.nickname)

            # Implement type ip-port from the original DNSEL design.
            if qtype == "ip-port":
                if router.will_exit_to(int(dest_ip), dest_port):
                    return defer.succeed((
                            [dns.RRHeader(self.root, dns.A, dns.IN, 1800,
                                          payload = dns.Record_A("127.0.0.2"))],
                            [dns.RRHeader(self.root, dns.NS, dns.IN, 1800,
                                          payload = dns.Record_NS(self.root))], # auth
                            # additional section: give the router's idhex and nickname
                            # as CNAME records.
                            [dns.RRHeader(self.root, dns.CNAME, dns.IN, 1800,
                                          payload = dns.Record_CNAME(router.idhex)),
                             dns.RRHeader(self.root, dns.CNAME, dns.IN, 1800,
                                          payload = dns.Record_CNAME(router.nickname))]
                            ))
            else:
                return nxdomain(name)
        else:
            return nxdomain(name)

if __name__ == "__main__":
    f = server.DNSServerFactory(authorities = [TorResolver("dnsel.torproject.org",
                                                           "torbel.csv")])
    if not "notcp" in sys.argv:
        reactor.listenTCP(53, f)
        log.debug("Listening for TCP queries on port 53.")

    reactor.listenUDP(53, dns.DNSDatagramProtocol(f))
    log.debug("Listening for UDP queries on port 53.")
    reactor.run()
