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

class RouterData:
    def __init__(self, torctl_router):
        #TorCtl.Router.__init__(self)
        self.router = torctl_router
        self.actual_ip   = None
        self.last_tested = int(time.time()) # None
        self.working_ports = [53, 443, 8080]
        self.failed_ports = [80,6667]

    def exit_policy(self):
        exitp = ""
        for exitline in self.router.exitpolicy:
            exitp += str(exitline) + ";"

        return exitp
        
    def export_csv(self, out):
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
        
        
    
class BELController(TorCtl.EventHandler):
    def __init__(self, host, port = 9051):
        TorCtl.EventHandler.__init__(self)
        try:
            self.host = host
            self.port = port
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
            self.conn = TorCtl.Connection(self.sock)
            self.conn.set_event_handler(self)
            self.torctl_thread = None
            self.routers = {}

        except socket.error, e:
            if "Connection refused" in e.args:
                log.error("Connection refused! Is Tor control port available?")
            raise # FIXME DO BETTER THINGS

    def start(self, passphrase):
        conn = self.conn
        conn.authenticate(passphrase)
        conn.set_events([TorCtl.EVENT_TYPE.CIRC,
                         TorCtl.EVENT_TYPE.STREAM,
                         TorCtl.EVENT_TYPE.ORCONN,
                         TorCtl.EVENT_TYPE.NEWDESC])

        log.info("Connected to running Tor instance (version %s) on %s:%d",
                 conn.get_info("version")['version'], self.host, self.port)
        log.info("Our IP address should be %s.", conn.get_info("address")["address"])

    def add_to_cache(self, ns):
        if "Exit" in ns.flags:
            try:
                router = self.conn.get_router(ns)
                if not router:
                    log.error("get_router returned null (bad descriptor?)")
                    return False
                
                router = RouterData(router)
                # Cache by router ID string.
                self.routers[router.router.idhex] = router

                return True

            except TorCtl.ErrorReply, e:
                log.error("Tor controller error: %s", e)
        else:
            return False


    def build_exit_cache(self):
        ns_list = self.conn.get_network_status()
        
        for ns in ns_list:
            self.add_to_cache(ns)

    def exit_count(self):
        return len(self.routers)

    def export_csv(self, gzip = False):
        try:
            if gzip:
                csv_file = gzip.open("bel.csv.gz", "w")
            else:
                csv_file = open("bel.csv", "w")
                
            out = csv.writer(csv_file, dialect = csv.excel)
            
            for router in self.routers.itervalues():
                router.export_csv(out)
            
        except IOError as (errno, strerror):
            log.error("I/O error writing to file %s: %s", csv_file.name, strerror)
            
    def join(self):
        if self.torctl_thread:
            self.torctl_thread.join()

    def close(self):
        self.conn.close()

    # EVENTS!
    def new_desc_event(self, event):
        for rid in event.idlist:
            ns = self.conn.get_network_status("id/" + rid)[0]
            if(self.routers.has_key(rid)):
                log.info("Exit %s to be updated", rid)
            if self.add_to_cache(ns):
                log.info("Added new exit %s.", rid)

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

    control = BELController(host, port)
    control.start("torbeltest")
    control.build_exit_cache()
    control.export_csv()

    # Sleep this thread (for now) while events come in on a separate
    # thread.  Close on SIGINT.
    try:
        while True:
            time.sleep(600)
            control.export_csv()
            log.info("Updated CSV export (%d routers).", control.exit_count())
    except KeyboardInterrupt:
        control.close()

    log.debug("Joining control connection thread.")
    control.join()
    
    return 0

if __name__ == "__main__":
    def usage():
        print "Usage: %s torhost ctlport" % sys.argv[0]
        sys.exit(1)

    if len(sys.argv) < 2:
        usage() # barf

    try:
        host = sys.argv[1]
        port = 9051 if len(sys.argv) < 3 else int(sys.argv[2])
    except ValueError:
        print "'%s' is not a valid port!" % sys.argv[2]
        sys.exit(2)

    torbel_start(host, port)
    sys.exit(0)
