#!/usr/bin/python
# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.

import logging
import signal, sys, errno
import select, socket, struct
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

# Set TorCtl log level (see TorCtl/TorUtil.py:def plog)
# Not sure how to actually set up the TorCtl config file...
TorCtl.loglevel = "INFO"

def set_log_level(_level):
    level = _level
    log.setLevel(level)
    ch.setLevel(level)

_OldRouterClass = TorCtl.Router
class RouterRecord(_OldRouterClass):
    def __init__(self, *args, **kwargs):
        _OldRouterClass.__init__(self, *args, **kwargs)
        self.actual_ip     = None
        self.last_tested   = 0 # 0 indicates the router is as yet untested
        self.working_ports = []
        self.failed_ports  = []
        self.circuit = None
        self.guard   = None

    def __eq__(self, other):
        return self.idhex == other.idhex

    def __ne__(self, other):
        return self.idhex != other.idhex
    
    def exit_policy(self):
        """ Collapse the router's ExitPolicy into one line, with each rule
            delimited by a semicolon (';'). """
        exitp = ""
        for exitline in self.exitpolicy:
            exitp += str(exitline) + ";"

        return exitp
        
    def export_csv(self, out):
        """ Export record in CSV format, given a Python csv.writer instance. """
        # If actual_ip is set, it differs from router.ip (advertised ExitAddress).
        ip = self.actual_ip if self.actual_ip else self.ip
        
        out.writerow([ip,
                      self.idhex,
                      self.nickname,
                      self.last_tested,
                      True,
                      self.exit_policy(),
                      self.working_ports,
                      self.failed_ports])

    def __str__(self):
        return "%s (%s)" % (self.idhex, self.nickname)
# BOOM
TorCtl.Router = RouterRecord

class Circuit:
    def __init__(self, guard, exit):
        self.streams = set()
        self.guard = guard
        self.exit  = exit
        self.condition = threading.Condition()

class socks4socket(socket.socket):
    SOCKS4_CONNECTED, SOCKS4_FAILED, SOCKS4_INCOMPLETE = range(3)

    def __init__(self, proxy_host, proxy_port):
        socket.socket.__init__(self, socket.AF_INET, socket.SOCK_STREAM)
        self.peer_host = None
        self.peer_port = None
        self.proxy_port = proxy_port
        self.proxy_host = proxy_host
        self.resp = ""
        
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
        try:
            self.resp += self.recv(8 - len(self.resp))
        except socket.error, e:
            # Interrupted by a signal, try again later.
            if e.errno == errno.EINTR:
                return self.SOCKS4_INCOMPLETE
        # If we receive less than the full SOCKS4 response, try again later.
        if len(self.resp) < 8:
            return self.SOCKS4_INCOMPLETE
        else:
            (status,) = struct.unpack('xBxxxxxx', self.resp)
            # 0x5A == success; 0x5B-5D == failure/rejected
            if status == 0x5a:        
                return self.SOCKS4_CONNECTED
            else:
                return self.SOCKS4_FAILED

class Controller(TorCtl.EventHandler):
    def __init__(self):
        TorCtl.EventHandler.__init__(self)
        self.host = config.tor_host
        self.port = config.control_port
        # Router cache contains all routers we know about, and is a
        #  superset of the latest consensus (we continue to track
        #  routers that have fallen out of the consensus for a short
        #  time).
        # Guard cache contains all routers in the consensus with the
        #  "Guard" flag.  We consider Guards to be the most reliable
        #  nodes for use as test circuit first hops.  We do not
        #  track guards after they have fallen out of the consensus.
        self.router_cache = {}
        self.guard_cache = {}
        # Lock controlling access to the consensus caches.
        self.consensus_cache_lock = threading.Lock()
        # test_ports should never be changed during the lifetime of the program
        # directly.  On SIGHUP test_ports may be changed in its entirety, but
        # ports may not be added or removed by any other method.
        self.test_ports = frozenset(config.test_port_list)
        self.test_sockets = {}
        self.circuits = {}
        self.pending_circuits = {}
        self.streams = {}
        self.test_exit = None

        self.init_sockets()

    def init_tor(self):
        """ Initialize important Tor options that may not be set in
            the user's torrc. """
        log.debug("Setting Tor options.")
        self.conn.set_option("__LeaveStreamsUnattached", "1")
        self.conn.set_option("FetchDirInfoEarly", "1")
        self.conn.set_option("FetchDirInfoExtraEarly", "1")
        self.conn.set_option("FetchUselessDescriptors", "1")

    def init_sockets(self):
        log.debug("Initializing test sockets.")
        for port in self.test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(0)
                sock.bind((config.test_bind_ip, port))
                self.test_sockets[port] = sock
            except socket.error, e:
                (err, message) = e.args
                log.error("Could not bind to test port %d: %s", port, message)
                if err == errno.EACCES:
                    log.error("Run TorBEL as root or a user able to bind to privileged ports.")
                elif err == errno.EADDRNOTAVAIL:
                    log.error("Please check your network settings.")
                    if config.test_bind_ip:
                        log.error("test_bind_ip in torbel_config.py must be assigned to a working network interface.")
                        log.error("The current value (%s) does not appear to be valid.",
                                  config.test_bind_ip)
                    else:
                        log.error("Could not bind to IPADDR_ANY.")
                # re-raise the error to be caught by the client.
                raise
            
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
                         TorCtl.EVENT_TYPE.NEWDESC,
                         TorCtl.EVENT_TYPE.NEWCONSENSUS])
        self.conn = conn
        self.init_tor()

        ## Build a list of Guard routers, so we have a list of reliable
        ## first hops for our test circuits.
        log.debug("Building router and guard caches from NetworkStatus documents.")
        self.__build_cache(self.conn.get_network_status())

        ## If the user has not configured test_host, use Tor's
        ## best guess at our external IP address.
        if not config.test_host:
            config.test_host = conn.get_info("address")["address"]
            
        log.info("Connected to running Tor instance (version %s) on %s:%d",
                 conn.get_info("version")['version'], self.host, self.port)
        log.info("Our IP address should be %s.", config.test_host)
        with self.consensus_cache_lock:
            log.debug("Tracking %d routers, %d of which are known guards.",
                      len(self.router_cache), len(self.guard_cache))

    def build_test_circuit(self, exit):
        """ Build a test circuit using exit and its associated guard node.
            Fail if exit.guard is not set. """
        if not exit.guard:
            return None

        hops = map(lambda r: "$" + r.idhex, [exit.guard, exit])
        exit.circuit = self.conn.extend_circuit(0, hops)
        return exit.circuit

    def exit_test(self, router):
        """ Perform port and IP tests on router.
            Will block until all port tests are finished.
            Can raise the following errors:
            socket.error
              - errno == errno.ECONNREFUSED: Tor refused our SOCKS connected.
        """
        test_data = {}
        test_ports = []
        recv_sockets = []
        self.test_exit = router

        test_started = time.time()
        bind_list = filter(lambda x: x is not None, self.test_sockets.values())

        for s in bind_list:
            ip, port = s.getsockname()
            
            if router.will_exit_to(config.test_host, port):
                log.debug("Setting up test to port %d.", port)
                # LISTEN OK
                s.listen(1)
                test_ports.append(port)
                # Randomly generate an eight-byte test data sequence.
                # We attempt to match this data with what we receive
                # from the exit node to verify its exit policy.
                test_data[port] = '%08x' % random.randint(0, 0xffffffff)
            
        if len(test_ports) == 0:
            log.debug("%s: no testable ports.", router.nickname)
            router.last_tested = int(time.time())
            return
        
        send_sockets_pending = []
        send_sockets = []
        # SOCKS4 connection to Tor
        # NOTE: Can raise socket.error, should be caught by caller.
        for port in test_ports:
            s = socks4socket(config.tor_host, config.tor_port)
            s.connect((config.test_host, port))
            send_sockets_pending.append(s)

        # Wait until we accept all connections and complete SOCKS4 handshakes:
        pending_sockets = bind_list + send_sockets_pending
        while len(pending_sockets) > 0:
            try:
                # Five seconds seems like a good timeout for the initial handshake and accept()
                # stage.  It depends on the longest acceptable time for Tor to attach the
                # stream to our already-built circuit.
                ready, ignore, me = select.select(pending_sockets, [], [], 5)
            except select.error, e:
                if e[0] != errno.EINTR:
                    ## FIXME: figure out a better wait to fail hard. re-raise?
                    log.error("%s: select() error: %s", router.nickname, e[1])
                continue
                    
            if len(ready) == 0:
                log.debug("%s: select() timeout (accept/SOCKS stage)!", router.nickname)
                break

            for s in ready:
                if s in bind_list:
                    # We're done waiting for this socket, remove it from our wait set.
                    pending_sockets.remove(s)
                    # Accept the connection and get the associated receive socket.
                    recv_sock, peer = s.accept()
                    recv_sockets.append(recv_sock)
                    # Record IP of our peer.
                    peer_ip, ignore     = recv_sock.getpeername()
                    ignore, listen_port = recv_sock.getsockname()
                        #test_sockets[port]["ip"] = ip
                    log.debug("%s: accepted connection from %s on port %d.",
                              router.nickname, peer_ip, listen_port)
                else:
                    # We got a SOCKS4 response from Tor.
                    # (1) get the reply, unpack the status value from it.
                    status = s.complete_handshake()
                    if status == socks4socket.SOCKS4_CONNECTED:
                        log.debug("SOCKS4 connect successful!")
                        # (2) we're successful: append to send list
                        # and remove from pending list.
                        send_sockets.append(s)
                        pending_sockets.remove(s)
                    elif status == socks4socket.SOCKS4_INCOMPLETE:
                        # Our response from Tor was incomplete;
                        # don't remove the socket from pending_sockets quite yet.
                        log.debug("Received partial SOCKS4 response.")
                    elif status == socks4socket.SOCKS4_FAILED:
                        # Tor rejected our connection.
                        # This could be for a number of reasons, including
                        # not being able to exit, the stream not getting
                        # attached in time (Tor times out unattached streams
                        # in two minutes according to control-spec.txt)
                        log.debug("SOCKS4 connect failed! :(")
                        pending_sockets.remove(s)
                        # Append port to router's failed_ports set.
                        router.failed_ports.append(s.getpeername()[1])
                
        # Perform actual tests.
        done = []
        while(len(recv_sockets + send_sockets) > 0):
            try:
                read_list, write_list, error = \
                    select.select(recv_sockets, send_sockets, [], 10)
            except select.error, e:
                # Socket, interrupted.
                # Why does socket.error have an errno attribute, but
                # select.error is a tuple? CONSISTENT
                if e[0] != errno.EINTR:
                    ## FIXME: fail harder
                    log.error("%s: select() error (testing stage): %s", router.nickname, e[0])
                continue

            if len(read_list + write_list) == 0:
                log.debug("%s: select() timeout (test data stage)!", router.nickname)
                break
            if read_list:
                for read_sock in read_list:
                    ip, port = read_sock.getsockname()
                    # TODO: Handle the case where the router exits on
                    # multiple differing IP addresses.
                    if router.actual_ip and router.actual_ip != ip:
                        log.debug("%s: multiple IP addresses, %s and %s (%s advertised)!",
                                  router.nickname, ip, router.actual_ip, router.ip)
                    router.actual_ip = ip

                    data          = test_data[port]
                    data_received = read_sock.recv(len(data))
                    if(data_received < len(data)):
                        # Partial response, check data so far.  If it's good,
                        # don't remove the socket from the select queue.
                        # Adjust the expected data for this port test and
                        # keep going.
                        if data_received == data[:len(data_received)]:
                            test_data[port] = data[len(data_received):]
                            log.debug("incomplete response! continuing")
                        continue

                    if(data == data_received):
                        log.debug("%s: port %d test succeeded!", router.nickname, port)
                        # Record successful port test.
                        router.working_ports.append(port)
                    else:
                        log.debug("%s: port %d test failed! Expected %s, got %s.",
                                  router.nickname, port, data, data_received)
                        router.failed_ports.append(port)
                        
                    recv_sockets.remove(read_sock)
                    done.append(read_sock)

            if write_list:
                for write_sock in write_list:
                    ip, port = write_sock.getpeername()
                    log.debug("%s: writing test data to port %d.", router.nickname, port)
                    write_sock.send(test_data[port])
                    send_sockets.remove(write_sock)
                    done.append(write_sock)

        log.debug("Closing sockets!")
        for sock in done:
            sock.close()

        test_completed = time.time()
        router.last_tested = int(test_completed)
        self.close_test_circuit(router)

        log.debug("%s: test completed in %f sec.", router.nickname, (test_completed - test_started))

    def close_test_circuit(self, router):
        """ Clean up router router after test. """
        if not router.circuit:
            return
        # Return guard to the guard pool.
        with self.consensus_cache_lock:
            self.guard_cache[router.guard.idhex] = router.guard
            # Return router to guard_cache if it was originally a guard.
            if "Guard" in router.flags:
                self.guard_cache[router.idhex] = router
        try:
            self.conn.close_circuit(router.circuit, reason = "Test complete")
        except TorCtl.ErrorReply, e:
            if "Unknown circuit" not in e.args[0]:
                # Re-raise unhandled errors.
                raise e
        # Unset circuit
        router.circuit = None

    def prepare_circuits(self):
        with self.consensus_cache_lock:
            routers = sorted(self.router_cache.values(), key = attrgetter("last_tested"))[0:4]
        
        # Build test circuits.
        with self.consensus_cache_lock:
            for router in routers:
                # If we are testing a guard, we don't want to use it as a guard for this
                # circuit.  Pop it temporarily from the guard_cache.
                if router.idhex in self.guard_cache:
                    self.guard_cache.pop(router.idhex)
                # Take guard out of available guard list.
                router.guard   = self.guard_cache.popitem()[1]
        for router in routers:
            cid = self.build_test_circuit(router)
            self.pending_circuits[cid] = router
        
        return routers
                
    def add_record(self, ns):
        """ Add a router to our cache, given its NetworkStatus instance. """
        try:
            router = self.conn.get_router(ns)
            # Bad router descriptor?
            if not router:
                return False

            router = RouterRecord(router)
            # Cache by router ID string.
            with self.consensus_cache_lock:
                # Update router record in-place to preserve references.
                # TODO: The way TorCtl does this is not thread-safe :/
                if router.idhex in self.router_cache:
                    self.router_cache[router.idhex].update_to(router)
                
                    # If the router is in our router_cache and was a guard, it was in
                    # guard_cache as well.
                    if router.idhex in self.guard_cache:
                        # Router is no longer considered a guard, remove it
                        # from our cache.
                        if "Guard" not in ns.flags:
                            del self.guard_cache[router.idhex]
                        # Otherwise, update the record.
                        else:
                            self.guard_cache[router.idhex].update_to(router)
                else:
                    # Add new record to router_cache.
                    self.router_cache[router.idhex] = router
                    # Add new record to guard_cache, if appropriate.
                    if "Guard" in ns.flags:
                        self.guard_cache[router.idhex] = router
            
            return True

        except TorCtl.ErrorReply, e:
            log.error("Tor controller error: %s", e)

    def record_exists(self, rid):
        """ Check if a router with a particular identity key hash is
            being tracked. """
        with self.consensus_cache_lock:
            return self.router_cache.has_key(rid)
            
    def __build_cache(self, nslist):
        """ Build the router cache up from what our Tor instance
            knows about the current network status. """
        for ns in nslist:
            self.add_record(ns)

    def record_count(self):
        """ Return the number of routers we are currently tracking. """
        with self.consensus_cache_lock:
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

            # FIXME: Is it safe to just take the itervalues list?
            with self.consensus_cache_lock:
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
            self.add_record(ns)

    def new_consensus_event(self, event):
        #self.__create_idmap(event.nslist)
        log.debug("Received NEWCONSENSUS event.")
        
    def circ_status_event(self, event):
        id = event.circ_id
        if event.status == "BUILT":
            if self.pending_circuits.has_key(id):
                log.debug("Successfully built circuit %d.", id)
                self.circuits[id] = self.pending_circuits[id]
                del self.pending_circuits[id]
            
        elif event.status == "FAILED":
            if self.circuits.has_key(id):
                log.error("Established test circuit %d failed.", id)
                del self.circuits[id]
            ## Circuit failed without being built.
            elif self.pending_circuits.has_key(id):
                log.error("Pending test circuit %d failed.", id)
                del self.pending_circuits[id]

        elif event.status == "CLOSED":
            if self.circuits.has_key(id):
                del self.circuits[id]
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
        if event.status == "NEW":
            if event.target_host == config.test_host and self.test_exit:
                circuit = self.test_exit.circuit
                self.conn.attach_stream(event.strm_id, circuit)
                log.debug("Attaching new stream %d to circuit %d (%s).",
                          event.strm_id, circuit, self.circuits[circuit].nickname)
        
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

        log.error("Socket error, aborting.")
        return 1

    except TorCtl.ErrorReply, e:
        log.error("Connection failed: %s", str(e))
        return 2

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
    exits = c.prepare_circuits()
    
    return c, exits

if __name__ == "__main__":
    def usage():
        print "Usage: %s [torhost [ctlport]]" % sys.argv[0]
        sys.exit(1)

    sys.exit(torbel_start())
