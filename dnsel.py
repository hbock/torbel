#!/usr/bin/env python
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

nxdomain = error.DomainError

class TorDNSServerFactory(server.DNSServerFactory):
    def __init__(self, zone, filename, *args, **kwargs):
        server.DNSServerFactory.__init__(self, *args, **kwargs)
        self.el = ExitList(filename)
        self.root = zone.split(".")
        self.root_name = zone
        
    def handleQuery(self, message, protocol, address):
        query = message.queries[0]
        ip, port = address

        return self.lookup(ip, query, None).addCallback(
            self.gotResolverResponse, protocol, message, address
        ).addErrback(
            self.gotResolverError, protocol, message, address
        )

    def exit_search(self, name, dest_ip, dest_port, tor_ip):
        log.debug("query tor IP %s, dest_ip %s, dest_port %d",
                  tor_ip, dest_ip, dest_port)

        router = self.el.tor_exit_search(int(tor_ip), dest_ip, dest_port)
        if router:
            log.debug("Request for %s:%d matches router %s(%s).",
                      tor_ip, dest_port, router.idhex, router.nickname)
            
            return ([dns.RRHeader(name, dns.A, dns.IN, 1800,
                                  payload = dns.Record_A("127.0.0.2"),
                                  auth = True)],
                    # Authority section
                    [dns.RRHeader(self.root_name, dns.NS, dns.IN, 1800,
                                  payload = dns.Record_NS(self.root_name))],
                    # Additional section: give the router's idhex and nickname
                    # as CNAME records.
                    [dns.RRHeader(self.root_name, dns.CNAME, dns.IN, 1800,
                                  payload = dns.Record_CNAME("id=" +router.idhex)),
                     dns.RRHeader(self.root_name, dns.CNAME, dns.IN, 1800,
                                  payload = dns.Record_CNAME("nickname=" + router.nickname))]
                    )

        raise nxdomain(name)

    def lookup(self, address, query, timeout):
        try:
            return defer.succeed(self._lookup(address, query, timeout))
        except error.DomainError, e:
            return defer.fail(failure.Failure(e))
        
    def _lookup(self, address, query, timeout):
        name = str(query.name)
        type = query.type
        cls = dns.IN

        # Refuse non-IN/A questions.
        if cls != dns.IN or type != dns.A:
            log.debug("We don't handle cls %s type %s", cls, type)
            return error.DNSQueryRefusedError()
        # Refuse requests for requests that aren't in our zone of authority.
        q = name.split(".")
        if q[-len(self.root):] != self.root:
            log.debug("We are authoritative and don't handle the TLD of %s",
                      repr(name))
            raise error.DNSQueryRefusedError()

        # Break off the root TLD and the query type.
        q = q[:-len(self.root)]
        qtype = q.pop()

        # DNSEL query type 1 "General IP:Port":
        # Format: {IP1}.{port}.{IP2}.ip-port.torhosts.example.com
        if qtype == "ip-port":
            # Attempt to parse the DNSEL request.
            try:
                tor_ip = IPAddress("%s.%s.%s.%s" % (q[3], q[2], q[1], q[0]))
                dest_port = int(q[4])
                dest_ip = IPAddress("%s.%s.%s.%s" % (q[8], q[7], q[6], q[5]))
            except:
                return None

            return self.exit_search(name, dest_ip, dest_port, tor_ip)
                
        elif qtype == "ip-port-list":
            dest_port = int(q[0])
            dest_ip = IPAddress("%s.%s.%s.%s" % (q[4], q[3], q[2], q[1]))
            log.debug("Query type %s, dest_ip %s, dest_port %d",
                      qtype, dest_ip, dest_port)

            addr_list = self.el.will_exit_to(int(dest_ip), dest_port)
            if addr_list:
                return ([dns.RRHeader(self.root_name, dns.A, dns.IN, 1800,
                                      payload = dns.Record_A(str(IPAddress(addr))),
                                      auth = True) for addr in addr_list],
                        # Authority section
                        [dns.RRHeader(self.root_name, dns.NS, dns.IN, 1800,
                                      payload = dns.Record_NS(self.root_name))],
                        []
                        )
            else:
                raise nxdomain(name)
            
        # DNSEL query type 3 "My IP, with port": 
        # Format: {IP}.{port}.me.torhosts.example.com
        elif qtype == "me":
            dest_port = int(q[4])
            tor_ip  = IPAddress("%s.%s.%s.%s" % (q[3], q[2], q[1], q[0]))
            return self.exit_search(name, address, dest_port, tor_ip)
        
        else:
            raise nxdomain(name)

if __name__ == "__main__":
    f = TorDNSServerFactory(zone = "dnsel.torproject.org", filename = "torbel.csv")

    if not "notcp" in sys.argv:
        reactor.listenTCP(53, f)
        log.debug("Listening for TCP queries on port 53.")

    reactor.listenUDP(53, dns.DNSDatagramProtocol(f))
    log.debug("Listening for UDP queries on port 53.")
    reactor.run()
