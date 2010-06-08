#!/usr/bin/python
# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.

import logging
import signal, sys
import select, socket, struct, socks
import threading
import random, time
import sys
import csv
from operator import attrgetter

from TorCtl import TorCtl
from TorCtl import PathSupport

try:
    import torbel_config as config
except ImportError:
    sys.stderr.write("Error: Could not load config file (torbel_config.py)!\n")
    sys.exit(1)

__version__ = "0.1"

# EXIT_SUCCESSFUL - Connection through the exit port was successful and the
#                   data received was identical to data sent.
# EXIT_REJECTED   - ExitPolicy rejects exit to the specified port.
# EXIT_FAILED     - ExitPolicy should accept traffic through the specified
#                   port but the traffic does not actually exit.
# EXIT_MANGLED    - ExitPolicy should accept traffic and we received data,
#                   but it was not the data we sent.
EXIT_SUCCESS, EXIT_REJECTED, EXIT_FAILED, EXIT_MANGLED = range(4)

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
        self.actual_ip     = None
        self.last_tested   = 0 # 0 indicates the router is as yet untested
        self.working_ports = []
        self.failed_ports  = []
        self.circuit = None
        self.guard   = None

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

class Circuit:
    def __init__(self, guard, exit):
        self.streams = set()
        self.guard = guard
        self.exit  = exit
        self.condition = threading.Condition()

class socks4socket(socket.socket):
    def __init__(self, proxy_host, proxy_port):
        socket.socket.__init__(self, socket.AF_INET, socket.SOCK_STREAM)
        self.peer_host = None
        self.peer_port = None
        self.proxy_port = proxy_port
        self.proxy_host = proxy_host

    def getpeername(self):
        return (self.peer_host, self.peer_port)

    def getproxyname(self):
        return (self.proxy_host, self.proxy_port)
    
    def connect(self, peer):
        self.peer_host, self.peer_port = peer
        socket.socket.connect(self, (self.proxy_host, self.proxy_port))
        self.send("\x04\x01" + struct.pack("!H", self.peer_port) +
                  socket.inet_aton(self.peer_host) + "\x00")
        # Boom I'm CRAZY
        self.setblocking(0)

    def complete_handshake(self):
        resp = self.recv(8)
        (status,) = struct.unpack('xBxxxxxx', resp)
        # 0x5A == success; 0x5B == failure/rejected
        if status == 0x5a:        
            return True

        return False

class Controller(TorCtl.EventHandler):
    def __init__(self):

        TorCtl.EventHandler.__init__(self)
        self.host = config.tor_host
        self.port = config.control_port
        self.router_cache = {}
        self.test_ports = config.test_port_list
        self.test_sockets = {}
        self.circuits = {}
        self.pending_circuits = {}
        self.streams = {}
        self.test_exit = None

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
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(0)
                sock.bind(("", port))
                self.test_sockets[port] = sock                

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
            config.test_host = conn.get_info("address")["address"]
            
        log.info("Connected to running Tor instance (version %s) on %s:%d",
                 conn.get_info("version")['version'], self.host, self.port)
        log.info("Our IP address should be %s.", config.test_host)
        log.debug("We currently know about %d guard nodes.", len(self.guard_list))

    def build_circuit(self, guard, exit):
        hops = map(lambda r: "$" + r.idhex, [guard, exit])
        return self.conn.extend_circuit(0, hops)

    def exit_test(self, router):
        tests = {}
        results = []
        test_ports = []
        recv_sockets = []
        self.test_exit = router
        exit = router.router # FIXME

        bind_list = filter(lambda x: x is not None, self.test_sockets.values())

        for s in bind_list:
            ip, port = s.getsockname()
            
            if not exit.will_exit_to(config.test_host, port):
                results.append((port, EXIT_REJECTED))

            else:
                log.debug("Setting up test to port %d.", port)
                # LISTEN OK
                s.listen(1)
                test_ports.append(port)
                tests[port] = {"port": port,
                               "data": '%08x' % random.randint(0, 0xffffffff)}
            
        send_sockets_pending = []
        send_sockets = []
        # SOCKS4 connection to Tor
        for port in test_ports:
            s = socks4socket(config.tor_host, config.tor_port)
            s.connect((config.test_host, port))
            send_sockets_pending.append(s)

        try:
            # Wait until we accept all connections and complete SOCKS4 handshakes:
            pending_sockets = bind_list + send_sockets_pending
            log.debug("%s: Waiting on %d sockets", exit.nickname, len(pending_sockets))
            while len(pending_sockets) > 0:
                ready, ignore, me = \
                    select.select(pending_sockets, [], [], 60)
                log.debug("%s: %d sockets are ready.", exit.nickname, len(ready))
                for s in ready:
                    if s in bind_list:
                        # We're done waiting for this socket, remove it from our wait set.
                        pending_sockets.remove(s)
                        # Accept the connection and get the associated receive socket.
                        recv_sock, peer = s.accept()
                        recv_sockets.append(recv_sock)
                        # Record IP of our peer.
                        ip, port = recv_sock.getpeername()
                        #test_sockets[port]["ip"] = ip
                        log.debug("%s: accepted connection from %s on port %d.",
                                  exit.nickname, ip, port)
                    else:
                        # We got a SOCKS4 response from Tor.
                        # (1) remove socket from pending list
                        pending_sockets.remove(s)
                        # (2) get the reply, unpack the status value from it.
                        if s.complete_handshake():
                            log.debug("SOCKS4 connect successful!")
                            send_sockets.append(s)
                        else:
                            log.debug("SOCKS4 connect failed! :(")
                
            # Perform actual tests.
            done = []
            while(len(tests) > 0):
                read_list, write_list, error = \
                    select.select(recv_sockets, send_sockets, [], 60)
                if read_list:
                    for read_sock in read_list:
                        ip, port = read_sock.getsockname()
                        test_data = tests[port]["data"]
                        data = read_sock.recv(len(test_data))

                        if(data == test_data):
                            log.debug("%s: port %d test succeeded!", exit.nickname, port)
                            tests[port]["result"] = EXIT_SUCCESS
                        else:
                            log.debug("%s: port %d test failed! Expected %s, got %s.",
                                      exit.nickname, port, test_data, data)
                            tests[port]["result"] = EXIT_MANGLED

                        recv_sockets.remove(read_sock)
                        done.append(read_sock)

                    results.append(tests[port])
                    # remove from our test array
                    del tests[port]
                if write_list:
                    for write_sock in write_list:
                        ip, port = write_sock.getpeername()
                        log.debug("%s: writing test data to port %d.", exit.nickname, port)
                        write_sock.send(tests[port]["data"])
                        #write_sock.close()
                        send_sockets.remove(write_sock)
                        done.append(write_sock)

            log.debug("Closing sockets!")
            for sock in done:
                sock.close()
                
        except socket.error, e:
            raise

        exit.last_tested = int(time.time())

    def prepare_circuits(self):
        exits = sorted(self.router_cache.values(), key = attrgetter("last_tested"))[0:3]
        
        # Build test circuits.
        for exit in exits:
            exit.guard   = self.guard_list.pop()
            exit.circuit = self.build_circuit(exit.guard, exit.router)
            self.pending_circuits[exit.circuit] = exit
        
        return exits
                
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
        # Close all currently bound test sockets.
        log.debug("Closing test sockets.")
        for sock in self.test_sockets.itervalues():
            sock.close()
        self.test_sockets.clear()

    # EVENTS!
    def new_desc_event(self, event):
        for rid in event.idlist:
            ns = self.conn.get_network_status("id/" + rid)[0]

            if self.record_exists(rid):
                log.debug("Updating router record for %s.", rid)
            else:
                log.debug("Adding new router record for %s.", rid)

            self.add_record(ns)

    def new_consensus_event(self, event):
        log.debug("Received NEWCONSENSUS event.")
        
    def circ_status_event(self, event):
        log.debug("Circuit %d : %s", event.circ_id, event.status)

        if event.status == "BUILT":
            id = event.circ_id
            if self.pending_circuits.has_key(id):
                self.circuits[id] = self.pending_circuits[id]
                del self.pending_circuits[id]
            
        elif event.status in ["FAILED", "CLOSED"]:
            ## Remove failed and closed circuits from our map.
            ## TODO: Notify threads that may be using the circuit
            ## it's going away.
            id = event.circ_id
            if self.circuits.has_key(id):
                del self.circuits[id]
            ## Circuit failed without being built.
            elif self.pending_circuits.has_key(id):
                del self.pending_circuits[id]
                
    def or_conn_status_event(self, event):
        ## TODO:
        ## We have to keep track of ORCONN status events
        ## and determine if our circuit extensions complete
        ## successfully.
        pass#print event

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

        if event.status == "NEW":
            if event.target_host == config.test_host and self.test_exit:
                circuit = self.test_exit.circuit
                self.conn.attach_stream(event.strm_id, circuit)
                log.debug("Attaching new stream %d to circuit %d (%s).",
                          event.strm_id, circuit, self.circuits[circuit].router.nickname)
        
    def msg_event(self, event):
        print "msg_event!", event.event_name

class ConfigurationError(Exception):
    """ TorBEL configuration error exception. """
    def __init__(self, message):
        self.message = message

## TODO: More sanity checks!
def config_check():
    """ Sanity check for TorBEL configuration. """
    c = ConfigurationError

    if not config.test_port_list:
        raise c("test_port_list must not be empty.")

    if not config.test_host:
        pass

    if config.control_port == config.tor_port:
        raise c("control_port and tor_port cannot be the same value.")

    # Ports must be positive integers not greater than 65,535.
    bad_ports = filter(lambda p: (type(p) is not int) or p < 0 or p > 0xffff,
                       config.test_port_list)
    if bad_ports:
        raise c("test_port_list: %s are not valid ports." % bad_ports)

def torbel_start():
    log.info("TorBEL v%s starting.", __version__)

    # Configuration check.
    try:
        config_check()
    except ConfigurationError, e:
        log.error("Configuration error: %s", e.message)
        return 1
    except AttributeError, e:
        log.error("Configuration error: missing value: %s", e.args[0])

    try:
        control = Controller()
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
    config_check()

    c = Controller()
    c.start()
    c.build_exit_cache()
    exits = c.prepare_circuits()
    
    return c, exits

if __name__ == "__main__":
    def usage():
        print "Usage: %s [torhost [ctlport]]" % sys.argv[0]
        sys.exit(1)

    sys.exit(torbel_start())
