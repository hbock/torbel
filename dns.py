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
        self.root = root.split(".")
        self.root_name = root
        
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
        q = name.split(".")
        if q[-len(self.root):] != self.root:
            log.debug("We are authoritative and don't handle the TLD of %s",
                      repr(name))
            return refused(name)

        # Break off the root TLD and the query type.
        q = q[:-len(self.root)]
        qtype = q.pop()

        # Query type 1 in torel-design.txt.
        if qtype == "ip-port":
            # Attempt to parse the DNSEL request.
            try:
                tor_ip = IPAddress("%s.%s.%s.%s" % (q[3], q[2], q[1], q[0]))
                dest_port = int(q[4])
                dest_ip = IPAddress("%s.%s.%s.%s" % (q[8], q[7], q[6], q[5]))
            # Otherwise barf back NXDOMAIN.
            except:
                return nxdomain(name)

            log.debug("Query type %s, tor IP %s, dest_ip %s, dest_port %d",
                      qtype, tor_ip, dest_ip, dest_port)

            router = self.el.is_tor_traffic(int(tor_ip), dest_port)
            if router and router.will_exit_to(int(dest_ip), dest_port):
                log.debug("Request for %s:%d matches router %s(%s).",
                          tor_ip, dest_port, router.idhex, router.nickname)

                return defer.succeed((
                        [dns.RRHeader(self.root_name, dns.A, dns.IN, 1800,
                                      payload = dns.Record_A("127.0.0.2"),
                                      auth = True)],
                        # Authority section
                        [dns.RRHeader(self.root_name, dns.NS, dns.IN, 1800,
                                      payload = dns.Record_NS(self.root_name))],
                        # Additional section: give the router's idhex and nickname
                        # as CNAME records.
                        [dns.RRHeader(self.root_name, dns.CNAME, dns.IN, 1800,
                                      payload = dns.Record_CNAME(router.idhex)),
                         dns.RRHeader(self.root_name, dns.CNAME, dns.IN, 1800,
                                      payload = dns.Record_CNAME(router.nickname))]
                        ))
            else:
                return nxdomain(name)

        elif qtype == "ip-port-list":
            dest_port = int(q[0])
            dest_ip = IPAddress("%s.%s.%s.%s" % (q[4], q[3], q[2], q[1]))
            log.debug("Query type %s, dest_ip %s, dest_port %d",
                      qtype, dest_ip, dest_port)

            addr_list = self.el.will_exit_to(int(dest_ip), dest_port)
            if addr_list:
                return defer.succeed((
                        [dns.RRHeader(self.root_name, dns.A, dns.IN, 1800,
                                      payload = dns.Record_A(str(IPAddress(addr))),
                                      auth = True) for addr in addr_list],
                        # Authority section
                        [dns.RRHeader(self.root_name, dns.NS, dns.IN, 1800,
                                      payload = dns.Record_NS(self.root_name))],
                        []
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
