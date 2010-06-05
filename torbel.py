#!/usr/bin/python
# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.

import logging
import signal
import socket
import socks
import threading
import random
import sys
import time
import csv

from TorCtl import TorCtl
from TorCtl import PathSupport

try:
    import torbel_config as config
except ImportError:
    sys.stderr.write("Error: Could not load config file (torbel_config.py)!\n")
    sys.exit(1)

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

class PortTest:
    SUCCESSFUL_EXIT, NO_EXIT, FAILED_EXIT, MANGLED_EXIT = range(4)
    
    def __init__(self, port, interface = ""):
        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.recv_socket.bind((interface, port))
        self.ip, self.port = self.recv_socket.getsockname()

    def test(self, router, exit_to):
        def listen_thread(listen_sock, test_data):
            listen_sock.listen(1)
            recv_sock, peer = listen_sock.accept()
            data = recv_sock.recv(8)
            peerip, peerport = recv_sock.getpeername()
            recv_sock.close()
            
            if(data == test_data):
                log.info("Test to %s:%d successful!!", peerip, peerport)
                
        def random_string():
            return '%08x' % random.randint(0, 0xffffffff)
                     
        if router.will_exit_to(exit_to, self.port):
            test_data = random_string()
            test_debug = "Test (%d, %s): " % (self.port, router.nickname)

            listen = threading.Thread(target = listen_thread,
                                      args = (self.recv_socket, test_data))
            log.debug(test_debug + "Starting listen thread")
            listen.start()
            torsock = socks.socksocket()
            log.debug(test_debug + "Connecting to exit via Tor.")
            torsock.connect((exit_to, self.port))
            log.debug(test_debug + "Connected, sending test data.")
            torsock.send(test_data)
            log.debug(test_debug + "Waiting for test result.")
            listen.join()
            log.debug(test_debug + "Test complete!")

            return PortTest.SUCCESSFUL_EXIT
                      
        else:
            return PortTest.NO_EXIT        
        
class Controller(TorCtl.EventHandler):
    def __init__(self):

        TorCtl.EventHandler.__init__(self)
        self.host = config.tor_host
        self.port = config.control_port
        self.router_cache = {}
        self.test_ports = config.test_port_list
        self.test_sockets = {}

        self.init_sockets()
        self.init_socks(self.host, config.tor_port)

    def init_tor(self):
        """ Initialize important Tor options that may not be set in
            the user's torrc. """
        log.debug("Setting Tor options.")
        self.conn.set_option("__LeaveStreamsUnattached", "1")
        self.conn.set_option("FetchDirInfoEarly", "1")
        #self.conn.set_option("FetchDirInfoExtraEarly", "1")

    def init_sockets(self):
        log.debug("Initializing test sockets.")
        for port in self.test_ports:
            try:
                self.test_sockets[port] = PortTest(port)

            except socket.error, e:
                log.warning("Could not bind to test port %d: %s. Continuing without this port test.", port, e.args)
                self.test_sockets[port] = None
            
    def init_socks(self, host = "localhost", orport = 9050):
        """ Initialize SocksiPy library to use the local Tor instance
            as the default SOCKS5 proxy. """
        socks.setdefaultproxy(config.tor_socks_type,
                              config.tor_host,
                              config.tor_port)

    def start(self, passphrase = config.control_password):
        """ Attempt to connect to the Tor control port with the given passphrase. """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        conn = TorCtl.Connection(self.sock)
        conn.set_event_handler(self)
        
        conn.authenticate(passphrase)
        ## We're interested in:
        ##   - Circuit events
        ##   - Stream events.
        ##   - Tor connection events.
        ##   - New descriptor events, to keep track of new exit routers.
        conn.set_events([TorCtl.EVENT_TYPE.CIRC,
                         TorCtl.EVENT_TYPE.STREAM,
                         TorCtl.EVENT_TYPE.ORCONN,
                         TorCtl.EVENT_TYPE.NEWDESC])
        self.conn = conn
        self.init_tor()

        ## Build a list of Guard routers, so we have a list of reliable
        ## first hops for our test circuits.
        self.guard_list = self.current_guard_list()

        ## If the user has not configured test_host, use Tor's
        ## best guess at our external IP address.
        if not config.test_host:
            self.test_host = conn.get_info("address")["address"]
        else:
            self.test_host = config.test_host
            
        self.test_circuit = None

        log.info("Connected to running Tor instance (version %s) on %s:%d",
                 conn.get_info("version")['version'], self.host, self.port)
        log.info("Our IP address should be %s.", self.test_host)
        log.debug("We currently know about %d guard nodes.", len(self.guard_list))

    def build_test_circuit(self, guard, exit):
        hops = map(lambda r: "$" + r.idhex, [guard, exit])
        return self.conn.extend_circuit(0, hops)

    def test(self, router):
        guard = self.guard_list[0]
        self.test_circuit = self.build_test_circuit(guard, router)
        log.debug("Created test circuit %d", self.test_circuit)
        return self.test_sockets[self.test_ports[0]].test(router, self.test_host)

    def add_record(self, ns):
        """ Add a router to our cache, given its NetworkStatus instance. """
        if "Exit" in ns.flags:
            try:
                router = self.conn.get_router(ns)
                ## Bad router descriptor?
                if not router:
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
            
    def build_exit_cache(self):
        """ Build the router cache up from what our Tor instance
            knows about the current network status. """
        for ns in self.current_exit_list():
            self.add_record(ns)

    def current_exit_list(self):
        return filter(lambda ns: "Exit" in ns.flags, self.conn.get_network_status())
    
    def current_guard_list(self):
        """ Return a list of all nodes with the "Guard" flag set. """
        return filter(lambda ns: "Guard" in ns.flags, self.conn.get_network_status())

    def record_count(self):
        """ Return the number of routers we are currently tracking. """
        return len(self.router_cache)

    def export_csv(self, gzip = False):
        """ Export current router cache in CSV format.  See data-spec
            for more information on export formats. """
        try:
            if gzip:
                csv_file = gzip.open(config.csv_export_file + ".gz", "w")
            else:
                csv_file = open(config.csv_export_file, "w")
                
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
        log.debug("Circuit %d : %s", event.circ_id, event.status)
        if event.status == "BUILT":
            self.conn.attach_stream(self.test_stream, self.test_circuit)

    def or_conn_status_event(self, event):
        ## TODO:
        ## We have to keep track of ORCONN status events
        ## and determine if our circuit extensions complete
        ## successfully.
        print event

    def stream_status_event(self, event):
        ## TODO:
        ## We must keep track of streams we have created via
        ## SOCKS.  After creating a stream, we will receive
        ## a stream status event.  We must check the target
        ## addresses against our bookkeeping on outgoing SOCKS
        ## sockets.
        ## If we are able to find a match, we should attach
        ## the stream to our existing circuits awaiting test
        ## streams.
        log.debug("Stream %d status %s circuit %s target %s",
                  event.strm_id, event.status,
                  event.circ_id, event.target_host)

        if event.status == "NEW" and self.test_circuit:
            log.debug("Attaching new stream to target host %s on circuit %d",
                      event.target_host, self.test_circuit)
            self.test_stream = event.strm_id
            
        
    def msg_event(self, event):
        print "msg_event!", event.event_name
    
def torbel_start():
    log.info("TorBEL v%s starting.", __version__)

    control = Controller()
    try:
        control.start()

    except socket.error, e:
        if "Connection refused" in e.args:
            log.error("Connection refused! Is Tor control port available?")
        return 1

    except TorCtl.ErrorReply, e:
        log.error("Connection failed: %s", str(e))
        return 2

    control.build_exit_cache()
    control.export_csv(gzip = config.csv_gzip)

    # Sleep this thread (for now) while events come in on a separate
    # thread.  Close on SIGINT.
    try:
        while True:
            time.sleep(600)
            control.export_csv(gzip = config.csv_gzip)
            log.info("Updated CSV export (%d routers).", control.record_count())
    except KeyboardInterrupt:
        control.close()

    return 0

def tests():
   c = Controller()
   c.start()
   c.build_exit_cache()
   r = c.router_cache.values()[0].router
   return c, c.test(r)

if __name__ == "__main__":
    def usage():
        print "Usage: %s [torhost [ctlport]]" % sys.argv[0]
        sys.exit(1)

    sys.exit(torbel_start())
