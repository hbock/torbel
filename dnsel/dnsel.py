#!/usr/bin/env python
# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.

# TorDNSEL-compatible DNS implementation using Twisted Names
# and the TorBEL query interface.
import os, sys, time
from datetime import datetime
from calendar import timegm

from zope.interface import implements
from twisted.names import server, dns, common, error
from twisted.internet import reactor, interfaces, defer
from twisted.python import failure

from torbel.dnsel import config
from torbel.query import ExitList
from torbel.utils import *
from torbel import logger

from ipaddr import IPAddress

log = logger.create_logger("tordnsel", logger.DEBUG)

nxdomain = error.DomainError

class TorDNSServerFactory(server.DNSServerFactory):
    def __init__(self, zone, filename, status, *args, **kwargs):
        server.DNSServerFactory.__init__(self, *args, **kwargs)
        self.el = ExitList(filename, status)

        if self.el.stale:
            log.info("Export %s likely stale.", filename)

        # Set up updates.
        nextUpdate = timegm(self.el.next_update.timetuple()) - time.time()
        if nextUpdate > 0:
            log.debug("Scheduling first update in %.1f seconds.", nextUpdate)
            reactor.callLater(nextUpdate, self.update)
        else:
            log.notice("Export file is not up-to-date. Trying again in 10 minutes.")
            reactor.callLater(10 * 60, self.update)
        
        self.root = zone.split(".")
        self.root_name = zone

    def update(self):
        next = self.el.update()
        nextUpdate = timegm(next.timetuple()) - time.time()
        if nextUpdate > 0:
            log.info("ExitList updated. Next update in %.1f seconds.", nextUpdate)
            reactor.callLater(nextUpdate, self.update)
        else:
            log.notice("Export file is not up-to-date. Trying again in 10 minutes.")
            reactor.callLater(10 * 60, self.update)
        
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
            
            return ([dns.RRHeader(name, dns.A, dns.IN, config.ttl,
                                  payload = dns.Record_A("127.0.0.2"),
                                  auth = True)],
                    # Authority section
                    [dns.RRHeader(self.root_name, dns.NS, dns.IN, config.ttl,
                                  payload = dns.Record_NS(self.root_name))],
                    # Additional section: give the router's idhex and nickname
                    # as CNAME records.
                    [dns.RRHeader(self.root_name, dns.CNAME, dns.IN, config.ttl,
                                  payload = dns.Record_CNAME("id=" +router.idhex)),
                     dns.RRHeader(self.root_name, dns.CNAME, dns.IN, config.ttl,
                                  payload = dns.Record_CNAME("nickname=" + router.nickname))]
                    )

        raise nxdomain(name)

    def lookup(self, address, query, timeout):
        try:
            return defer.succeed(self._lookup(address, query, timeout))
        except error.DomainError, e:
            return defer.fail(failure.Failure(e))
        # Return NXDOMAIN on any parser failure.
        except:
            return defer.fail(failure.Failure(nxdomain(str(query.name))))
        
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
        if config.enable_ip_port and qtype == "ip-port":
            # Attempt to parse the DNSEL request.
            tor_ip = IPAddress("%s.%s.%s.%s" % (q[3], q[2], q[1], q[0]))
            dest_port = int(q[4])
            dest_ip = IPAddress("%s.%s.%s.%s" % (q[8], q[7], q[6], q[5]))

            return self.exit_search(name, dest_ip, dest_port, tor_ip)
                
        elif config.enable_ip_port_list and qtype == "ip-port-list":
            dest_port = int(q[0])
            dest_ip = IPAddress("%s.%s.%s.%s" % (q[4], q[3], q[2], q[1]))
            log.debug("Query type %s, dest_ip %s, dest_port %d",
                      qtype, dest_ip, dest_port)

            addr_list = self.el.will_exit_to(int(dest_ip), dest_port)
            if addr_list:
                return ([dns.RRHeader(self.root_name, dns.A, dns.IN, config.ttl,
                                      payload = dns.Record_A(str(IPAddress(addr))),
                                      auth = True) for addr in addr_list],
                        # Authority section
                        [dns.RRHeader(self.root_name, dns.NS, dns.IN, config.ttl,
                                      payload = dns.Record_NS(self.root_name))],
                        []
                        )
            else:
                raise nxdomain(name)
            
        # DNSEL query type 3 "My IP, with port": 
        # Format: {IP}.{port}.me.torhosts.example.com
        elif config.enable_me and qtype == "me":
            dest_port = int(q[4])
            tor_ip  = IPAddress("%s.%s.%s.%s" % (q[3], q[2], q[1], q[0]))
            return self.exit_search(name, address, dest_port, tor_ip)
        
        else:
            raise nxdomain(name)

def config_check():
    c = ConfigurationError

    if not any([config.listen_tcp, config.listen_udp]):
        raise c("You must enable at least one of listen_tcp, listen_udp.")

    for var in ["ttl", "listen_port"]:
        check_type(config, var, int, lambda x: x > 0, "Expected positive integer.")
    for var in ["listen_tcp", "listen_udp", "enable_ip_port",
                "enable_me", "enable_ip_port_list"]:
        check_type(config, var, bool)
    for var in ["zone", "listen_host", "export_prefix"]:
        check_type(config, var, str)
        
    if not any([config.enable_ip_port,
                config.enable_me,
                config.enable_ip_port_list]):
        raise c("You must enable at least one query type.")

if __name__ == "__main__":
    # First try to verify the DNSEL configuration.
    try:
        config_check()
    except ConfigurationError, e:
        log.error("Configuration error: %s", e.message)
        sys.exit(1)
    except AttributeError, e:
        log.error("Configuration error: missing value: %s", e.args[0])
        sys.exit(1)

    found_export = False
    for ext in (".csv", ".json"):
        try:
            f = TorDNSServerFactory(zone = config.zone,
                                    filename = config.export_prefix + ext,
                                    status   = config.export_prefix + ".status")
            found_export = True
            break
        # If we can't open one export, try to fall back on the other.
        except IOError, e:
            pass

    if not found_export:
        log.critical("Couldn't open any export file with prefix '%s'. Bailing.",
                     config.export_prefix)
        sys.exit(2)

    if config.listen_tcp:
        reactor.listenTCP(config.listen_port, f)
        log.notice("Listening for TCP queries on port %d.", config.listen_port)

    if config.listen_udp:
        reactor.listenUDP(config.listen_port, dns.DNSDatagramProtocol(f))
        log.notice("Listening for UDP queries on port 53.")

    if os.geteuid() == 0:
        try:
            uid, gid = uid_gid_lookup(config.user, config.group)
            drop_privileges(uid, gid)
        except ConfigurationError, e:
            log.critical("Configuration error: %s", e.message)
            
    reactor.run()
