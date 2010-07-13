# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.
# TorBEL Exit List import and query implementation.
import csv
import gzip
import struct, re
import time, datetime
from socket import inet_aton, inet_ntoa
from logger import *

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
    def __init__(self, csv_row = ()):
        if csv_row:
            r = csv_row
            self.exit_address    = int(r[0])
            self.idhex           = r[1]
            if len(self.idhex) < 40:
                raise ValueError("Invalid router key hash! '%s'" % self.idhex)
            self.nickname        = r[2]
            self.last_tested     = int(r[3])
            self.in_consensus    = (r[4] == "True")
            self.exit_policy     = r[5]
            self.working_ports   = port_list_from_string(r[6])
            self.failed_ports    = port_list_from_string(r[7])

class ParseError(Exception):
    def __init__(self, record_num, *args, **kwargs):
        Exception.__init__(*args, **kwargs)
        self.record_num = record_num
        
class ExitList:
    def __init__(self, csv_file = None):
        self.cache_ip = {}
        self.cache_id = {}

        if csv_file:
            self.import_csv(csv_file)
            
    def _clear_cache(self):
        self.cache_ip.clear()
        self.cache_id.clear()
        
    def import_csv(self, filename):
        """ Import a TorBEL export file in CSV format, as specified in
            the TorBEL data-spec document. """
        if filename.endswith(".gz"):
            infile = gzip.open(filename, "rb")
        else:
            infile = open(filename, "rb")

        reader = csv.reader(infile, dialect = "excel")
        for row in reader:
            try:
                router = Router(csv_row = row)
            except (ValueError, TypeError), e:
                raise ParseError(router_num = record)
            
            self.cache_ip[router.exit_address] = router
            self.cache_id[router.idhex]    = router

    def is_tor_traffic(self, ip, port):
        """ Returns False if no Tor router is known that exits from the IP address
            'ip' and for TCP port 'port'.
            ip must be numeric (see socket.inet_aton if you work with IP strings). """
        if ip in self.cache_ip:
            router = self.cache_ip[ip]
            if port in router.working_ports:
                return router

        return False
