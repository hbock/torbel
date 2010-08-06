#!/usr/bin/python
# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.
# TorBEL Exit List import and query implementation.
import csv
import gzip
import struct, re
import time, datetime
import ipaddr
import sys
from socket import inet_aton, inet_ntoa
from logger import *

if sys.version_info >= (2,6):
    import json

log = get_logger("query")

def ip_from_string(string):
    return struct.unpack(">I", inet_aton(string))[0]

plist_re = re.compile("\[((\d{1,5}, *)*(\d{1,5} *)?)\]")
def port_list_from_string(string):
    """ Convert a port list string, as specified in data-spec section 2.1. """
    m = plist_re.match(string)
    if m:
        inner = m.group(1)
        if len(inner):
            return map(int, inner.split(","))
        else:
            return []
    else:
        raise ValueError("'%s' is not a port list." % string)

class Router:
    def __init__(self, data):
        self.exit_address  = data["ExitAddress"]
        self.idhex         = data["RouterID"]
        self.nickname      = data["Nickname"]
        if len(self.idhex) < 40:
            raise ValueError("Invalid router key hash! '%s'" % self.idhex)
        self.last_tested   = data["LastTestedTimestamp"]
        self.in_consensus  = data["InConsensus"]
        self.exit_policy   = self._build_exit_policy(data["ExitPolicy"])
        self.working_ports = data["WorkingPorts"]
        self.failed_ports  = data["FailedPorts"]

    def _build_exit_policy(self, policy_list):
        return [ExitPolicyRule(line) for line in policy_list]

    def exit_policy_match(self, ip, port):
        # Per dir-spec.txt: "The rules are considered in order"
        for rule in self.exit_policy:
            if rule.match(ip, port):
                return rule.accept

        # Per dir-spec.txt: "if no rule matches, the address
        # will be accepted."
        return True

    def will_exit_to(self, ip, port):
        # FIXME: In the case that TorBEL has not actually tested this exit,
        # we will trust the router's exit policy.  This may or may not be
        # the Right Thing To Do.
        if type(port) is not int or port < 1 or port > 65535:
            raise ValueError("Port must be an integer between 1 and 65535.")

        if port in self.working_ports:
            return True
        elif port in self.failed_ports:
            return False

        return self.exit_policy_match(ip, port)

    def will_exit_to_ports(self, ip, port_list):
        return all(map(lambda port: self.will_exit_to(ip, port), port_list))

class ParseError(Exception):
    def __init__(self, record_num, exception, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)
        self.record_num = record_num
        self.exception = exception

# A rough pattern that will always match the exitpattern parse tree
# specified in dir-spec.txt.  Further checking must be done to properly
# validate ip4, ip4mask, ip6spec, etc. nonterminals.
_exitline = re.compile(r"^(accept|reject) (.+)")
_portspec = re.compile(r"^\d{1,5}|\d{1,5}-\d{1,5}$")
_addrspec = re.compile(r"^\[?([\d:.]+)\]?(/[\d:.]+)?$")
class ExitPolicyRule:
    def __init__(self, line):
        self.port_low, self.port_high = -1, -1
        self.ip = None

        ar = _exitline.match(line)
        if ar:
            self.accept = ar.group(1) == "accept"
            self.reject = not self.accept
            exitpattern = ar.group(2)

        else:
            raise ValueError("Invalid exit policy line: %s" % line)

        try:
            addr, port = exitpattern.split(":")
        except ValueError:
            raise ValueError("Invalid exit policy line.")

        if port == "*":
            self.port_low, self.port_high = 0, 65535
        else:
            if not _portspec.match(port):
                raise ValueError("Invalid port specification in exit policy line.")

            if "-" in port:
                self.port_low, self.port_high = map(int, port.split("-"))
                
            else:
                self.port_low = self.port_high = int(port)

        if addr == "*":
            self.network = ipaddr.IPNetwork("0.0.0.0/0")

        else:
            try:
                if addr.rfind("/") != -1:
                    self.network = ipaddr.IPNetwork(_addrspec.sub(r"\1\2", addr))
                    self.address = None
                else:
                    self.network = None
                    self.address = ipaddr.IPAddress(addr)

            except ValueError:
                raise ValueError("Invalid address specification in exit policy line.")
                
    def match(self, ip, port):
        if port >= self.port_low and port <= self.port_high:
            if self.network and ipaddr.IPAddress(ip) in self.network:
                return True
            elif self.address and ipaddr.IPAddress(ip) == self.address:
                return True
            
class ExitList:
    def __init__(self, filename):
        self.cache_ip = {}
        self.cache_id = {}

        self.list_import(filename)
            
    def _clear_cache(self):
        self.cache_ip.clear()
        self.cache_id.clear()

    def list_import(self, filename):
        if filename.endswith(".gz"):
            infile = gzip.open(filename, "rb")
            filename = filename[:3]
        else:
            infile = open(filename, "rb")

        if filename.endswith(".csv"):
            self.import_csv(infile)
        elif filename.endswith(".json"):
            if sys.version_info < (2, 6):
                raise ValueError("JSON support requires Python 2.6 or higher.")
            self.import_json(infile)
    def add_record(self, data):
        router = Router(data)
        self.cache_ip[router.exit_address] = router
        self.cache_id[router.idhex]        = router

    def import_csv(self, infile):
        """ Import a TorBEL export file in CSV format, as specified in
            the TorBEL data-spec document. """
        reader = csv.reader(infile, dialect = "excel")
        record = 1
        for r in reader:
            try:
                data = {
                    "ExitAddress": int(r[0]),
                    "RouterID":    r[1],
                    "Nickname":    r[2],
                    "LastTestedTimestamp": int(r[3]),
                    "InConsensus": r[4] == "True",
                    "ExitPolicy":  r[5].split(";"),
                    "WorkingPorts": port_list_from_string(r[6]),
                    "FailedPorts":  port_list_from_string(r[7])
                    }

                self.add_record(data)
                
            except (ValueError, TypeError), e:
                raise ParseError(record_num = record, exception = e)

            record += 1

    def import_json(self, infile):
        """ Import records from an open stream with JSON data. """
        data = json.load(infile)
        record_count = 1
        for record in data:
            try:
                self.add_record(record)
            except (ValueError, TypeError), e:
                raise ParseError(record_num = record_count, exception = e)

            record_count += 1

    def is_tor_traffic(self, ip, port):
        """ Returns False if no Tor router is known that exits from the IP address
            'ip' and for TCP port 'port'.
            ip must be numeric (see socket.inet_aton if you work with IP strings). """
        if ip in self.cache_ip:
            router = self.cache_ip[ip]
            if port in router.working_ports:
                return router

        return False

    def will_exit_to(self, ip, port):
        """ Returns a list of IP addresses in integer form that are likely to
            exit to the IP address 'ip' on port 'port'. """
        return [rip for rip, router in self.cache_ip.iteritems() if \
                    router.will_exit_to(ip, port)]

    def will_exit_to_ports(self, ip, port_list):
        """ Returns a list of IP addresses in integer form that are likely to
            exit to the IP address 'ip' on every port in 'port_list'. """
        return [rip for rip, router in self.cache_ip.iteritems() if \
                    router.will_exit_to_ports(ip, port_list)]
    

# A quick test driver.
# When called like so:
#   ./query.py targets 8.8.8.8:22
# This driver will write to 'export-8.8.8.8:22' all exit IP addresses that
# are likely to be exit nodes from Tor that can exit to 8.8.8.8 on port 22,
# one exit IP address per line.
#
# When called like:
#   ./query.py targets 8.8.8.8:22 4.2.2.1:80,443
# This driver will write two files; export-8.8.8.8:22 will be the same as above,
# but export-4.2.2.1:80,443 will contain all exits that will exit to 4.2.2.1
# on ports 80 _and_ 443.  Perhaps it should write two files, one for each port?
if __name__ == "__main__":
    def usage():
        print "Usage: %s targets ip:port1[,port2,...] [ip2:port1[,port2,...]] [...]" % sys.argv[0]
        sys.exit(1)

    if len(sys.argv) < 3:
        usage()

    command = sys.argv[1]

    if command == "targets":
        targetspec_list = sys.argv[2:]
        target_list = []
        
        for target in targetspec_list:
            try:
                ip, portspec = target.split(":")
                portlist = map(int, portspec.split(","))
                for port in portlist:
                    if port < 1 or port > 65535:
                        print "Invalid port %d. Must be between 1 and 65535." % port
                        sys.exit(1)

            except ValueError, TypeError:
                print "Invalid target '%s'!" % target
                usage()
                sys.exit(1)

            target_list.append((ipaddr.IPAddress(ip), portlist))

        exit_list = ExitList(csv_file = "bel_export.csv")
        for ip, portlist in target_list:
            output = open("export-" + str(ip) + ":" + ",".join(map(str, portlist)), "w")
            source_list = exit_list.will_exit_to_ports(ip, portlist)
            for source in source_list:
                output.write("%s\n" % str(ipaddr.IPAddress(source)))

            output.close()

    else:
        usage()
        sys.exit(1)

    sys.exit(0)
