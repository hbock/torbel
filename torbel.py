#!/usr/bin/python
# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.

import logging
import signal
import socket
import sys
import time
import csv

from TorCtl import TorCtl
from TorCtl import PathSupport

__version__ = "0.1"

## Set up logging
## TODO: this shouldn't be global. (?)
level = logging.DEBUG
log = logging.getLogger("TorBEL")
log.setLevel(level)
ch = logging.StreamHandler()
ch.setLevel(level)
ch.setFormatter(logging.Formatter("%(asctime)s %(name)s.%(levelname)s: %(message)s")) 
log.addHandler(ch)

def set_log_level(_level):
    level = _level
    log.setLevel(level)
    ch.setLevel(level)

class RouterRecord:
    def __init__(self, torctl_router):
        #TorCtl.Router.__init__(self)
        self.router = torctl_router
        self.actual_ip   = None
        self.last_tested = 0 # 0 indicates the router is as yet untested
        self.working_ports = []
        self.failed_ports = []

    @property
    def id(self):
        """ Router identity key, hashed and base64 encoded. """
        return self.router.idhex

    def exit_policy(self):
        """ Collapse the router's ExitPolicy into one line, with each rule
            delimited by a semicolon (';'). """
        exitp = ""
        for exitline in self.router.exitpolicy:
            exitp += str(exitline) + ";"

        return exitp
        
    def export_csv(self, out):
        """ Export record in CSV format, given a Python csv.writer instance. """
        # If actual_ip is set, it differs from router.ip (advertised ExitAddress).
        ip = self.actual_ip if self.actual_ip else self.router.ip
        
        out.writerow([ip,
                      self.router.idhex,
                      self.router.nickname,
                      self.last_tested,
                      True,
                      self.exit_policy(),
                      self.working_ports,
                      self.failed_ports])

    def __str__(self):
        return "%s (%s)" % (self.router.idhex, self.router.nickname)

class Controller(TorCtl.EventHandler):
    def __init__(self, host, port = 9051):
        TorCtl.EventHandler.__init__(self)
        self.host = host
        self.port = port
        self.router_cache = {}

    def start(self, passphrase):
        """ Attempt to connect to the Tor control port with the given passphrase. """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        conn = TorCtl.Connection(self.sock)
        conn.set_event_handler(self)
        
        conn.authenticate(passphrase)
        conn.set_events([TorCtl.EVENT_TYPE.CIRC,
                         TorCtl.EVENT_TYPE.STREAM,
                         TorCtl.EVENT_TYPE.ORCONN,
                         TorCtl.EVENT_TYPE.NEWDESC])
        self.conn = conn

        log.info("Connected to running Tor instance (version %s) on %s:%d",
                 conn.get_info("version")['version'], self.host, self.port)
        log.info("Our IP address should be %s.", conn.get_info("address")["address"])

    def add_record(self, ns):
        """ Add a router to our cache, given its NetworkStatus instance. """
        if "Exit" in ns.flags:
            try:
                router = self.conn.get_router(ns)
                if not router:
                    log.error("get_router returned null (bad descriptor?)")
                    return False
                
                router = RouterRecord(router)
                # Cache by router ID string.
                self.router_cache[router.id] = router

                return True

            except TorCtl.ErrorReply, e:
                log.error("Tor controller error: %s", e)
        else:
            return False

    def record_exists(self, rid):
        """ Check if a router with a particular identity key hash is
            being tracked. """
        return self.router_cache.has_key(rid)
    
    def clear_exit_cache(self):
        """ Clear the current router cache. """
        self.router_cache.clear()
        
    def build_exit_cache(self):
        """ Build the router cache up from what our Tor instance
            knows about the current network status. """
        ns_list = self.conn.get_network_status()

        for ns in ns_list:
            self.add_record(ns)

    def record_count(self):
        """ Return the number of routers we are currently tracking. """
        return len(self.router_cache)

    def export_csv(self, gzip = False):
        """ Export current router cache in CSV format.  See data-spec
            for more information on export formats. """
        try:
            if gzip:
                csv_file = gzip.open("bel.csv.gz", "w")
            else:
                csv_file = open("bel.csv", "w")
                
            out = csv.writer(csv_file, dialect = csv.excel)
            
            for router in self.router_cache.itervalues():
                router.export_csv(out)
            
        except IOError as (errno, strerror):
            log.error("I/O error writing to file %s: %s", csv_file.name, strerror)
            
    def close(self):
        """ Close the connection to the Tor control port. """
        self.conn.close()

    # EVENTS!
    def new_desc_event(self, event):
        for rid in event.idlist:
            ns = self.conn.get_network_status("id/" + rid)[0]

            if self.record_exists(rid):
                log.debug("Updating router record for %s.", rid)
            else:
                log.debug("Adding new router record for %s.", rid)

            self.add_record(ns)

    def circ_status_event(self, event):
        print event

    def or_conn_status_event(self, event):
        print event

    def stream_status_event(self, event):
        #print "Stream event ", event.purpose
        pass
        
    def msg_event(self, event):
        print "msg_event!", event.event_name
    

def torbel_start(host, port):
    log.info("TorBEL v%s starting.", __version__)

    control = Controller(host, port)
    try:
        control.start("torbeltest")

    except socket.error, e:
        if "Connection refused" in e.args:
            log.error("Connection refused! Is Tor control port available?")
        return 1

    except TorCtl.ErrorReply, e:
        log.error("Connection failed: %s", str(e))
        return 2

    control.build_exit_cache()
    control.export_csv()

    # Sleep this thread (for now) while events come in on a separate
    # thread.  Close on SIGINT.
    try:
        while True:
            time.sleep(600)
            control.export_csv()
            log.info("Updated CSV export (%d routers).", control.record_count())
    except KeyboardInterrupt:
        control.close()

    return 0

if __name__ == "__main__":
    def usage():
        print "Usage: %s [torhost [ctlport]]" % sys.argv[0]
        sys.exit(1)

    try:
        host = "localhost" if len(sys.argv) < 2 else sys.argv[1]
        port = 9051 if len(sys.argv) < 3 else int(sys.argv[2])

    except ValueError:
        print "'%s' is not a valid port!" % sys.argv[2]
        sys.exit(2)

    sys.exit(torbel_start(host, port))
