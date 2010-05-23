#!/usr/bin/python
# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.

import logging
import signal
import socket
import sys
import time

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
    
class BELController(TorCtl.EventHandler):
    def __init__(self, host, port = 9051):
        TorCtl.EventHandler.__init__(self)
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
            self.conn = TorCtl.Connection(self.sock)
            self.conn.set_event_handler(self)
            self.torctl_thread = None

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

        log.info("Connected to running Tor instance (version %s)",
                 conn.get_info("version")['version'])
        log.info("Our IP address should be %s.", conn.get_info("address")["address"])

    def print_exit_lists(self):
        ns_list = self.conn.get_network_status()
                
        for ns in ns_list:
            if "Exit" in ns.flags:
                try:
                    router = self.conn.get_router(ns)
                    if not router:
                        log.error("get_router returned null (bad descriptor?)")
                        continue

                    print "Exit Node \"%s\"\n\tAdvertised IP: %s\n\tPublished on: %s\n\tExitPolicy - %d lines" % \
                        (router.nickname, router.ip,
                         router.published, len(router.exitpolicy))
                    #for exitline in router.exitpolicy:
                    #    print exitline
                except TorCtl.ErrorReply, e:
                    log.error("Tor controller error: %s", e)

        
    def join(self):
        if self.torctl_thread:
            self.torctl_thread.join()

    def close(self):
        self.conn.close()

    # EVENTS!
    def new_desc_event(self, event):
        print event, event.idlist, event.arrived_at

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
    control.print_exit_lists()

    # Sleep this thread (for now) while events come in on a separate
    # thread.  Close on SIGINT.
    try:
        while True:
            time.sleep(1000)
    except KeyboardInterrupt:
        control.close()

    log.debug("Joining control connection thread.")
    control.join()
    
    return 0

if __name__ == "__main__":
    def usage():
        print "Usage: %s torhost ctlport" % sys.argv[0]
        sys.exit(1)

    if len(sys.argv) < 3:
        usage() # barf

    try:
        host = sys.argv[1]
        port = int(sys.argv[2])
    except ValueError:
        print "'%s' is not a valid port!" % sys.argv[2]
        sys.exit(2)

    try:
        torbel_start(host, port)
        sys.exit(0)
        
    except Exception, e:
        print "Unhandled error condition (%s): %s" % (type(e), e)
        sys.exit(2)
