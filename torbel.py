#!/usr/bin/python
# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.

# We come from the __future__.
from __future__ import with_statement

import logging
import sys, os, pwd, grp, resource
import signal, sys, errno
import select, socket, struct
import threading
import random, time
import csv
import Queue
from operator import attrgetter
from copy import copy

from TorCtl import TorCtl, TorUtil
from TorCtl import PathSupport

# torbel submodules
from logger import *
from socks4 import socks4socket

try:
    import torbel_config as config
except ImportError:
    sys.stderr.write("Error: Could not load config file (torbel_config.py)!\n")
    sys.exit(1)

__version__ = "0.1"

set_log_level(config.log_level)
log = get_logger("torbel",
                 syslog = config.log_syslog,
                 stdout = config.log_stdout,
                 file   = config.log_file)

_OldRouterClass = TorCtl.Router
class RouterRecord(_OldRouterClass):
    class Test:
        def __init__(self, ports):
            self.start_time = 0
            self.end_time = 0
            self.test_ports = ports
            self.working_ports = set()
            self.failed_ports  = set()
            self.circuit_failure = False

        def passed(self, port):
            self.working_ports.add(port)

        def failed(self, port):
            self.failed_ports.add(port)

        def start(self):
            self.start_time = time.time()
            return self

        def end(self):
            self.end_time = time.time()
            return self

        def is_complete(self):
            return self.test_ports <= (self.working_ports | self.failed_ports)

    def __init__(self, *args, **kwargs):
        _OldRouterClass.__init__(self, *args, **kwargs)
        self.actual_ip     = None
        self.last_test = self.Test(self.exit_ports(config.test_host,
                                                   config.test_port_list))
        self.current_test = None
        self.circuit = None  # Router's current circuit ID, if any.
        self.guard   = None  # Router's entry guard.  Only set with self.circuit.
        self.stale   = False # Router has fallen out of the consensus.
        self.stale_time = 0  # Time when router fell out of the consensus.

        self.circuit_failures  = 0
        self.circuit_successes = 0
        self.guard_failures  = 0
        self.guard_successes = 0

    def __eq__(self, other):
        return self.idhex == other.idhex

    def __ne__(self, other):
        return self.idhex != other.idhex

    def is_exit(self):
        return len(self.last_test.test_ports) != 0

    def new_test(self):
        """ Create a new RouterRecord.Test as current_test. """
        self.current_test = self.Test(self.exit_ports(config.test_host,
                                                      config.test_port_list))

    def end_current_test(self):
        """ End current test and move current_test to last_test. Returns
            the completed RouterRecord.Test object. """
        if self.current_test:
            self.current_test.end()
            # Transfer test results over.
            self.last_test = self.current_test
            self.current_test = None
            return self.last_test

    def update_to(self, new):
        #_OldRouterClass.update_to(self, new)
        # TorCtl.Router.update_to is currently broken (7/2/10) and overwrites
        # recorded values for torbel.RouterRecord-specific attributes.
        # This causes important stuff like guard fields to be overwritten
        # and we die very quickly.
        # TODO: There should be a better way to update a router - perhaps
        # directly from a router descriptor?
        for attribute in ["idhex", "nickname", "bw", "desc_bw",
                          "exitpolicy", "flags", "down",
                          "ip", "version", "os", "uptime",
                          "published", "refcount", "contact",
                          "rate_limited", "orhash"]:
            self.__dict__[attribute] = new.__dict__[attribute]
        # ExitPolicy may have changed on NEWCONSENSUS. Update
        # ports that may be accessible.
        self.test_ports = self.exit_ports(config.test_host, config.test_port_list)

    def exit_ports(self, ip, port_set):
        """ Return the set of ports that will exit from this router to ip
            based on the cached ExitPolicy. """
        return set(filter(lambda p: self.will_exit_to(ip, p), port_set))

    def exit_policy(self):
        """ Collapse the router's ExitPolicy into one line, with each rule
            delimited by a semicolon (';'). """
        return ";".join(map(str, self.exitpolicy))
        
    def export_csv(self, out):
        """ Export record in CSV format, given a Python csv.writer instance. """
        # If actual_ip is set, it differs from router.ip (advertised ExitAddress).
        ip = self.actual_ip if self.actual_ip else self.ip

        # From data-spec:
        out.writerow([ip,                           # ExitAddress
                      self.idhex,                   # RouterID
                      self.nickname,                # RouterNickname
                      int(self.last_test.end_time), # LastTestedTimestamp
                      not self.stale,               # InConsensus
                      self.exit_policy(),           # ExitPolicy
                      list(self.last_test.working_ports), # WorkingPorts
                      list(self.last_test.failed_ports)]) # FailedPorts

    def __str__(self):
        return "%s (%s)" % (self.idhex, self.nickname)
# BOOM
TorCtl.Router = RouterRecord

class Stream:
    def __init__(self):
        self.socket      = None
        self.router      = None
        self.strm_id     = None
        self.circ_id     = None
        self.source_port = None
        
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
        self.consensus_cache_lock = threading.RLock()
        # test_ports should never be changed during the lifetime of the program
        # directly.  On SIGHUP test_ports may be changed in its entirety, but
        # ports may not be added or removed by any other method.
        self.test_ports = frozenset(config.test_port_list)
        self.test_bind_sockets = set()
        # Send and receive testing socket set, with associated mutex and condition
        # variable.
        self.recv_sockets = set()
        self.send_sockets = set()
        self.send_recv_lock = threading.RLock()
        self.send_recv_cond = threading.Condition(self.send_recv_lock)
        # Pending SOCKS4 socket set, with associated mutex and condition variable.
        self.send_sockets_pending = set()
        self.send_pending_lock = threading.RLock()
        self.send_pending_cond = threading.Condition(self.send_pending_lock)
        # Stream data lookup.
        self.streams_by_source = {}
        self.streams_by_id = {}
        self.streams_lock = threading.RLock()

        ## Circuit dictionaries.
        # Established circuits under test.
        self.circuits = {}
        # Circuits in the process of being built.
        self.pending_circuits = {}
        self.pending_circuit_lock = threading.RLock()
        self.pending_circuit_cond = threading.Condition(self.pending_circuit_lock)

        self.terminated = False
        self.tests_enabled = False
        self.test_thread = None
        self.tests_completed = 0
        self.tests_started = 0

    def init_tor(self):
        """ Initialize important Tor options that may not be set in
            the user's torrc. """
        log.debug("Setting Tor options.")
        self.conn.set_option("__LeaveStreamsUnattached", "1")
        self.conn.set_option("FetchDirInfoEarly", "1")
        self.conn.set_option("FetchDirInfoExtraEarly", "1")
        self.conn.set_option("FetchUselessDescriptors", "1")

    def init_tests(self):
        """ Initialize testing infrastructure - sockets, resource limits, etc. """
        # Bind to test ports.
        log.debug("Binding to test ports.")
        # Sort to try privileged ports first, since sets have no
        # guaranteed ordering.
        for port in sorted(self.test_ports):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setblocking(0)
                sock.bind((config.test_bind_ip, port))
                self.test_bind_sockets.add(sock)
            except socket.error, e:
                (err, message) = e.args
                log.error("Could not bind to test port %d: %s", port, message)
                if err == errno.EACCES:
                    log.error("Run TorBEL as a user able to bind to privileged ports.")
                elif err == errno.EADDRNOTAVAIL:
                    log.error("Please check your network settings.")
                    if config.test_bind_ip:
                        log.error("test_bind_ip in torbel_config.py must be assigned to an active network interface.")
                        log.error("The current value (%s) does not appear to be valid.",
                                  config.test_bind_ip)
                    else:
                        log.error("Could not bind to IPADDR_ANY.")
                # re-raise the error to be caught by the client.
                raise

        if os.getuid() == 0:
            os.setgid(config.gid)
            os.setuid(config.uid)
            log.debug("Dropped root privileges to uid=%d.", config.uid)

        # Set RLIMIT_NOFILE to its hard limit; we want to be able to
        # use as many file descriptors as the system will allow.
        # NOTE: Your soft/hard limits are inherited from the root user!
        # The root user does NOT always have unlimited file descriptors.
        # Take this into account when editing /etc/security/limits.conf.
        (soft, hard) = resource.getrlimit(resource.RLIMIT_NOFILE)
        log.log(VERBOSE1, "RLIMIT_NOFILE: soft = %d, hard = %d", soft, hard) 
        if soft < hard:
            log.debug("Increasing RLIMIT_NOFILE soft limit to %d.", hard)
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))                

        log.debug("Initializing test threads.")
        T = threading.Thread
        self.test_thread      = T(target = Controller.testing_thread, name = "Test",
                                  args = (self,))
        self.circuit_thread   = T(target = Controller.circuit_build_thread,
                                  name = "Circuits", args = (self,))
        self.listen_thread    = T(target = Controller.listen_thread, name = "Listen",
                                  args = (self,))
        self.stream_thread    = T(target = Controller.stream_management_thread,
                                  name = "Stream", args = (self,))

    def run_tests(self):
        """ Start the test thread. """
        if self.test_thread:
            if self.test_thread.isAlive():
                log.error("BUG: Test thread already running!")
                return
            self.circuit_thread.start()
            self.listen_thread.start()
            self.stream_thread.start()
            self.test_thread.start()

        else:
            log.error("BUG: Test thread not initialized!")

    def is_testing_enabled(self):
        """ Is testing enabled for this Controller instance? """
        return self.tests_enabled

    def tests_running(self):
        """ Returns True if all threads associated with testing are
            alive. """
        return self.tests_enabled and \
            self.circuit_thread.isAlive() and \
            self.listen_thread.isAlive()  and \
            self.stream_thread.isAlive()  and \
            self.test_thread.isAlive()
    
    def start(self, tests = True, passphrase = config.control_password):
        """ Attempt to connect to the Tor control port with the given passphrase. """
        # Initiaze tests first (bind() etc) so we can bork early without waiting
        # for torctl init stuff.
        self.tests_enabled = tests
        if self.tests_enabled:
            self.init_tests()

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
        if config.torctl_debug:
            self.conn.debug(open("TorCtlDebug-%d" % int(time.time()), "w+"))
 
        self.init_tor()

        ## If the user has not configured test_host, use Tor's
        ## best guess at our external IP address.
        if not config.test_host:
            config.test_host = conn.get_info("address")["address"]
            
        ## Build a list of Guard routers, so we have a list of reliable
        ## first hops for our test circuits.
        log.debug("Building router and guard caches from NetworkStatus documents.")
        self._update_consensus(self.conn.get_network_status())

        log.info("Connected to running Tor instance (version %s) on %s:%d",
                 conn.get_info("version")['version'], self.host, self.port)
        log.info("Our IP address should be %s.", config.test_host)
        with self.consensus_cache_lock:
            log.debug("Tracking %d routers, %d of which are guards.",
                      len(self.router_cache), len(self.guard_cache))

        # Finally start testing.
        if self.tests_enabled:
            self.run_tests()

    def build_test_circuit(self, exit):
        """ Build a test circuit using exit and its associated guard node.
            Fail if exit.guard is not set. """
        if not exit.guard:
            raise ValueError("Guard not set for exit %s (%s).", exit.nickname, exit.idhex)

        hops = map(lambda r: "$" + r.idhex, [exit.guard, exit])
        exit.circuit = self.conn.extend_circuit(0, hops)
        return exit.circuit

    def completed_test(self, router):
        """ Close test circuit associated with router.  Restore
            associated guard to guard_cache. """
        router.circuit_successes += 1
        router.guard.guard_successes += 1
        self.test_cleanup(router)
        self.tests_completed += 1

        if self.tests_completed % 200 == 0:
            self.export_csv()

        test = router.last_test
        log.info("Test %d done [%.1f/min]: %s: %d passed, %d failed: %d circ success, %d failure.",
                 self.tests_completed,
                 self.tests_completed / ((time.time() - self.tests_started) / 60),
                 router.nickname, len(test.working_ports), len(test.failed_ports),
                 router.circuit_successes, router.circuit_failures)

    def stream_fetch(self, id = None, source_port = None):
        if not (id or source_port):
            raise ValueError("stream_fetch takes at least one of id and source_port.")

        else:
            with self.streams_lock:
                return self.streams_by_source[source_port] if source_port \
                    else self.streams_by_id[id]
        
    def stream_remove(self, id = None, source_port = None):
        if not (id or source_port):
            raise ValueError("stream_remove takes at least one of id and source_port.")

        else:
            with self.streams_lock:
                if source_port:
                    stream = self.streams_by_source[source_port]
                    del self.streams_by_source[source_port]
                    if stream.strm_id:
                        del self.streams_by_id[stream.strm_id]
                elif id:
                    stream = self.streams_by_id[id]
                    del self.streams_by_id[id]

            return stream
        
    def test_cleanup(self, router):
        """ Clean up router after test - close circuit (if built), return
            circuit entry guard to cache, and return router to guard_cache if
            it is also a guard. """
        # Return guard to the guard pool.
        router.end_current_test()
        with self.consensus_cache_lock:
            self.guard_cache[router.guard.idhex] = router.guard
            # Return router to guard_cache if it was originally a guard.
            if "Guard" in router.flags:
                self.guard_cache[router.idhex] = router
        # If circuit was built for this router, close it.
        if router.circuit:
            try:
                self.conn.close_circuit(router.circuit, reason = "Test complete")
            except TorCtl.ErrorReply, e:
                msg = e.args[0]
                if "Unknown circuit" in msg:
                    pass
                else:
                    # Re-raise unhandled errors.
                    raise e
        
            # Unset circuit
            router.circuit = None

    def stream_management_thread(self):
        log.debug("Starting stream management thread.")

        def remove_pending_socket(socket):
            with self.send_pending_lock:
                self.send_sockets_pending.remove(sock)
            
        while not self.terminated:
            # Grab pending SOCKS4 sockets.
            with self.send_pending_cond:
                while len(self.send_sockets_pending) == 0:
                    self.send_pending_cond.wait()
                # Boom, we have pending SOCKS4 sockets! Copy that shit.
                pending_sockets = copy(self.send_sockets_pending)
                failed_socks = filter(lambda s: s.failed, pending_sockets)
                for sock in failed_socks:
                    sock.close()
                    pending_sockets.remove(sock)
                    self.send_sockets_pending.remove(sock)
            try:
                ready, ign, error = select.select(pending_sockets, [], pending_sockets, 2)
            except select.error, e:
                if e[0] == errno.EBADF:
                    log.error("Bad file descriptor (select.error).")
                    continue
                elif e[0] != errno.EINTR:
                    # FIXME: handle errors better.
                    log.error("select() error: %s", e[1])
                    raise
                else:
                    continue
            except socket.error, e:
                # We get this probably only when the descriptor was closed
                # before being removed from pending_sockets (should be
                # not possible with proper locking?)
                if e.errno == errno.EBADF:
                    log.error("Bad file descriptor (socket.error).")
                    continue

            for sock in error:
                log.debug("ZOOM socket error!")

            # We timed out - doesn't matter, keep going.
            if len(ready) == 0:
                log.log(VERBOSE2, "Timeout waiting on %d sockets.", len(pending_sockets))
                continue

            for sock in ready:
                # Get router info.
                try:
                    remote_ip, target_port = sock.getpeername()
                    local_ip,  source_port = sock.getsockname()
                except socket.error, e:
                    if e.errno == errno.EBADF:
                        log.debug("Bad file descriptor?")
                        continue

                # We got a (possibly partial) SOCKS4 response from Tor.
                # (1) get the reply, unpack the status value from it.
                status = sock.complete_handshake()
                if status == socks4socket.SOCKS4_CONNECTED:
                    log.log(VERBOSE1, "SOCKS4 connect successful!")
                    # (2) we're successful: append to send list
                    # and remove from pending list.
                    with self.send_pending_lock:
                        self.send_sockets_pending.remove(sock)
                    # Append to send list and notify testing thread.
                    with self.send_recv_cond:
                        self.send_sockets.add(sock)
                        self.send_recv_cond.notify()

                elif status == socks4socket.SOCKS4_INCOMPLETE:
                    # Our response from Tor was incomplete;
                    # don't remove the socket from pending_sockets quite yet.
                    log.debug("Received partial SOCKS4 response.")
                    continue

                elif status == socks4socket.SOCKS4_FAILED:
                    # Tor rejected our connection.
                    # This could be for a number of reasons, including
                    # not being able to exit, the stream not getting
                    # attached in time (Tor times out unattached streams
                    # in two minutes according to control-spec.txt)
                    with self.send_pending_lock:
                        self.send_sockets_pending.remove(sock)
                    # NOTE: Don't check for test completion here.
                    # We check STREAM events for more information on
                    # failure and record test status there.
                    log.log(VERBOSE1, "(%d) SOCKS4 connect failed!",
                            target_port)

        log.debug("Terminating thread.")

    def listen_thread(self):
        """ Thread that waits for new connections from the Tor network. """
        log.debug("Starting listen thread.")
        
        listen_set = set()
        for sock in self.test_bind_sockets:
            ip, port = sock.getsockname()
            
            # LISTEN OK.  Is 20 too large of a backlog? Testing will tell.
            sock.listen(20)
            listen_set.add(sock)

            # Randomly generate an eight-byte test data sequence.
            # We attempt to match this data with what we receive
            # from the exit node to verify its exit policy.
            #test_data[port] = '%08x' % random.randint(0, 0xffffffff)
        while not self.terminated:
            try:
                # While we generally don't time out on established connections,
                # we have to check for our termination condition.  For now, do
                # this every two seconds.
                ready, ignore, error = select.select(listen_set, [], listen_set, 2)

            except select.error, e:
                (err, strerror) = e
                if err != errno.EINTR:
                    ## FIXME: figure out a better wait to fail hard. re-raise?
                    log.error("select() error: %s", strerror)
                    raise
                else:
                    continue

            for sock in ready:
                # Record IP of our peer.
                recv_sock, (host, port) = sock.accept()
                ignore, listen_port = recv_sock.getsockname()

                log.log(VERBOSE2, "Accepted connection from %s on port %d.",
                        host, listen_port)
                # Add our new socket to the recv list and notify
                # the testing thread.
                with self.send_recv_cond:
                    self.recv_sockets.add(recv_sock)
                    self.send_recv_cond.notify()

            for sock in error:
                log.error("Socket %d error!", sock.fileno())

            # Close accept()ed file descriptors when terminating.
            if self.terminated:
                for sock in listen_set:
                    sock.close()

        log.debug("Terminating thread.")
            
    def testing_thread(self):
        log.debug("Starting test thread.")
        self.tests_started = time.time()
        data_recv = {}
        
        while not self.terminated:
            with self.send_recv_cond:
                # Wait on send_recv_cond to stall while we're not waiting on
                # test sockets.
                while len(self.recv_sockets) + len(self.send_sockets) == 0:
                    log.debug("waiting for new test sockets.")
                    self.send_recv_cond.wait()
                    
                recv_socks = copy(self.recv_sockets)
                send_socks = copy(self.send_sockets)

            try:
                recv_list, send_list, error = \
                    select.select(recv_socks, send_socks, [], 1)
            except select.error, e:
                # Why does socket.error have an errno attribute, but
                # select.error is a tuple? CONSISTENT
                if e[0] != errno.EINTR:
                    ## FIXME: fail harder
                    log.error("select() error: %s", e[0])
                    raise
                # socket, interrupted.  Carry on.
                continue

            if len(recv_list) + len(send_list) == 0:
                log.log(VERBOSE2, "Timeout waiting on %d send and %d recv sockets.",
                        len(send_socks), len(recv_socks))
                continue
            
            for sock in recv_list:
                try:
                    ip, ignore  = sock.getpeername()
                    my_ip, port = sock.getsockname()
                except socket.error, e:
                    # Socket borked before we could actually get anything
                    # out of it.  Bail.
                    if e.errno == errno.ENOTCONN:
                        with self.send_recv_lock:
                            self.recv_sockets.remove(sock)
                            sock.close()
                            continue
                    else:
                        raise

                # Append received data to current data for this socket.
                if sock not in data_recv:
                    data_recv[sock] = ""
                data = data_recv[sock]
                try:
                    data_recv[sock] += sock.recv(40 - len(data))
                except socket.error, e:
                    if e.errno == errno.ECONNRESET:
                        with self.send_recv_lock:
                            log.error("Connection reset by %s.", ip)
                            self.recv_sockets.remove(sock)
                            sock.close()
                            continue
                
                if(len(data) < 40):
                    continue

                if data in self.router_cache:
                    router = self.router_cache[data]
                    # Record successful port test.
                    router.current_test.passed(port)
                    (ip_num,) = struct.unpack(">I", socket.inet_aton(ip))
                    router.actual_ip = ip_num

                    # TODO: Handle the case where the router exits on
                    # multiple differing IP addresses.
                    if router.actual_ip and router.actual_ip != ip_num:
                        log.debug("%s: multiple IP addresses, %s and %s (%s advertised)!",
                                  router.nickname, ip_num, router.actual_ip, router.ip)

                    if router.current_test.is_complete():
                        self.completed_test(router)

                else:
                    log.debug("(port %d): Unknown router %s! Failure?",
                              port, data)
                    
                # We're done with this socket. Close and wipe associated test data.
                # Also remove from our recv_sockets list.
                with self.send_recv_lock:
                    self.recv_sockets.remove(sock)
                    del data_recv[sock]
                    sock.close()

            for send_sock in send_list:
                dest_ip, port    = send_sock.getpeername()
                sip, source_port = send_sock.getsockname()

                stream = self.stream_fetch(source_port = source_port)
                router = stream.router
                log.log(VERBOSE1, "(%s, %d): sending test data.", router.nickname, port)

                try:
                    send_sock.send(router.idhex)
                except socket.error, e:
                    # Tor reset our connection?
                    if e.errno == errno.ECONNRESET:
                        log.debug("(%s, %d): Connection reset by peer.",
                                  router.nickname, port)
                        with self.send_recv_lock:
                            self.send_sockets.remove(send_sock)
                        # Remove from stream bookkeeping.
                        self.stream_remove(source_port = source_port)
                        send_sock.close()
                        continue

                # We wrote complete data without error.
                # Remove socket from select() list and
                # prepare for close.
                with self.send_recv_lock:
                    self.send_sockets.remove(send_sock)
                # Remove from stream bookkeeping.
                self.stream_remove(source_port = source_port)
                send_sock.close()

        log.debug("Terminating thread.")

    def circuit_build_thread(self):
        log.debug("Starting circuit builder thread.")

        def cleanup_circuits():
            ctime = time.time()
            with self.pending_circuit_lock:
                for idhex, router in self.circuits.iteritems():
                    if not router.current_test:
                        continue
                    if (ctime - router.current_test.start_time) > 3 * 60:
                        test = router.current_test
                        ndone = len(test.working_ports) + len(test.failed_ports)
                        log.debug("Closing old circuit %d (%s, %d done, %d needed - %s)",
                                  router.circuit, router.nickname, ndone,
                                  len(test.test_ports) - ndone,
                                  router.idhex)
                        self.test_cleanup(router)

        max_pending_circuits = 10
        # Base max running circuits on the total number of file descriptors
        # we can have open (hard limit returned by getrlimit) and the maximum
        # number of file descriptors per circuit, adjusting for possible pending
        # circuits, TorCtl connection, stdin/out, and other files.
        max_files = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        max_running_circuits = min(config.max_built_circuits,
                                   max_files / len(self.test_ports) - max_pending_circuits - 5)

        while not self.terminated:
            with self.pending_circuit_cond:
                # Block until we have less than ten circuits built or
                # waiting to be built.
                # TODO: Make this configurable?
                while len(self.pending_circuits) >= max_pending_circuits or \
                        len(self.circuits) >= max_running_circuits:
                    self.pending_circuit_cond.wait(3.0)
                    if self.terminated:
                        return
                    elif len(self.circuits) >= max_running_circuits:
                        log.debug("Too many circuits! Cleaning up possible dead circs.")
                        cleanup_circuits()

                log.debug("Build more circuits! (%d pending, %d running).",
                          len(self.pending_circuits),
                          len(self.circuits))

            with self.consensus_cache_lock:
                # Build 3 circuits at a time for now.
                # TODO: Make this configurable?
                routers = filter(lambda r: not r.current_test and r.last_test.test_ports,
                                 self.router_cache.values())
            log.debug("%d routers are testable", len(routers))
            routers = sorted(routers,
                             key = lambda r: r.last_test.start_time)[0:max_pending_circuits]

            with self.consensus_cache_lock:
                # Build test circuits.
                for router in routers:
                    # If we are testing a guard, we don't want to use it as a guard for
                    # this circuit.  Pop it temporarily from the guard_cache.
                    if router.idhex in self.guard_cache:
                        self.guard_cache.pop(router.idhex)

                    # Take guard out of available guard list.
                    router.guard = self.guard_cache.popitem()[1]

            for router in routers:
                cid = self.build_test_circuit(router)
                # Start test.
                router.new_test()
                router.current_test.start()
                with self.pending_circuit_lock:
                    self.pending_circuits[cid] = router

        log.debug("Terminating thread.")

    def add_to_cache(self, router):
        """ Add a router to our cache, given its NetworkStatus instance. """
        with self.consensus_cache_lock:
            # Update router record in-place to preserve references.
            # TODO: The way TorCtl does this is not thread-safe :/
            if router.idhex in self.router_cache:
                # Router was stale.  Since it is again in the consensus,
                # it is no longer stale.  Keep the last stale time, though,
                # in case we eventually want to detect flapping exits.
                if router.stale:
                    router.stale = False
                self.router_cache[router.idhex].update_to(router)
                
                # If the router is in our router_cache and was a guard, it was in
                # guard_cache as well.
                if router.idhex in self.guard_cache:
                    # Router is no longer considered a guard, remove it
                    # from our cache.
                    if "Guard" not in router.flags:
                        del self.guard_cache[router.idhex]
                    # Otherwise, update the record.
                    else:
                        self.guard_cache[router.idhex].update_to(router)
            else:
                # Add new record to router_cache.
                self.router_cache[router.idhex] = router
                # Add new record to guard_cache, if appropriate.
                if "Guard" in router.flags:
                    self.guard_cache[router.idhex] = router
            
        return True

    def record_exists(self, rid):
        """ Check if a router with a particular identity key hash is
            being tracked. """
        with self.consensus_cache_lock:
            return self.router_cache.has_key(rid)
            
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
                    if router.is_exit():
                        router.export_csv(out)
            
        except IOError, e:
            (errno, strerror) = e
            log.error("I/O error writing to file %s: %s", csv_file.name, strerror)
            
    def close(self):
        """ Close the connection to the Tor control port and end testing.. """
        self.terminated = True
        if self.tests_enabled:
            log.info("Joining test threads.")
            # Notify any sleeping threads.
            for cond in (self.send_recv_cond, self.send_pending_cond,
                     self.pending_circuit_cond):
                with cond:
                    cond.notify()
            self.test_thread.join()
            self.circuit_thread.join()
            self.listen_thread.join()
            self.stream_thread.join()
            log.info("All threads joined.")
        log.info("Closing Tor controller connection.")
        self.conn.close()
        # Close all currently bound test sockets.
        if self.test_bind_sockets:
            log.debug("Closing test sockets.")
            for sock in self.test_bind_sockets:
                sock.close()

    def stale_routers(self):
        with self.consensus_cache_lock:
            return filter(lambda r: r.stale, self.router_cache.values())
        
    # EVENTS!
    def new_desc_event(self, event):
        for rid in event.idlist:
            try:
                ns     = self.conn.get_network_status("id/" + rid)[0]
                router = self.conn.get_router(ns)
                self.add_to_cache(router)
            except TorCtl.ErrorReply, e:
                log.error("NEWDESC: Controller error: %s", str(e))

    def _update_consensus(self, nslist):
        # hbock: borrowed from TorCtl.py:ConsensusTracker
        # Routers can fall out of our consensus five different ways:
        # 1. Their descriptors disappear
        # 2. Their NS documents disappear
        # 3. They lose the Running flag
        # 4. They list a bandwidth of 0
        # 5. They have 'opt hibernating' set
        with self.consensus_cache_lock:
            new_routers = self.conn.read_routers(nslist)
            
            old_ids = set(self.router_cache.keys())
            new_ids = set(map(attrgetter("idhex"), new_routers))

            # Update cache with new consensus.
            for router in new_routers:
                self.add_to_cache(router)

            # Now handle routers with missing descriptors/NS documents.
            # --
            # this handles cases (1) and (2) above.  (3), (4), and (5) are covered by
            # checking Router.down, but the router is still listed in our directory
            # cache.  TODO: should we consider Router.down to be a "stale" router
            # to be considered for dropping from our record cache, or should we wait
            # until the descriptor/NS documents disappear?
            dropped_routers = old_ids - new_ids
            if dropped_routers:
                log.debug("%d routers are now stale (of %d, %.1f%%).",
                          len(dropped_routers), len(old_ids),
                          100.0 * len(dropped_routers) / float(len(old_ids)))
            for id in dropped_routers:
                router = self.router_cache[id]
                if router.stale:
                    # Check to see if it has been out-of-consensus for long enough to
                    # warrant dropping it from our records.
                    cur_time = int(time.time())
                    if((cur_time - router.stale_time) > config.stale_router_timeout):
                        log.debug("update consensus: Dropping stale router from cache. (%s)",
                                  router.idhex)
                        del self.router_cache[id]
                else:
                    # Record router has fallen out of the consensus, and when.
                    router.stale      = True
                    router.stale_time = int(time.time())
                        
                # Remove guard from guard_cache if it has fallen out of the consensus.
                if id in self.guard_cache:
                    log.debug("update consensus: dropping missing guard from guard_cache. (%s)",
                              router.idhex)
                    del self.guard_cache[id]


    def new_consensus_event(self, event):
        log.debug("Received NEWCONSENSUS event.")
        self._update_consensus(event.nslist)
        
    def circ_status_event(self, event):
        id = event.circ_id
        if event.status == "BUILT":
            with self.pending_circuit_cond:
                if self.pending_circuits.has_key(id):
                    router = self.pending_circuits[id]
                    del self.pending_circuits[id]
                    # Notify CircuitBuilder thread that we have
                    # completed building a circuit and we could
                    # need to pre-build more.
                    self.pending_circuit_cond.notify()
                else:
                    return
                
                log.log(VERBOSE1, "Successfully built circuit %d for %s.",
                        id, router.nickname)
                self.circuits[id] = router
                
                for port in router.exit_ports(config.test_host, config.test_port_list):
                    # Initiate SOCKS4 connection to Tor.
                    # NOTE: Can raise socket.error, should be caught by caller.
                    # TODO: socks4socket.connect can block.  Mayhaps since we're
                    # using a separate thread now, we can more easily do a fully
                    # asynchronous SOCKS4 handshake.
                    sock = socks4socket(config.tor_host, config.tor_port)
                    try:
                        sock.connect((config.test_host, port))
                    except socket.gaierror, e:
                        log.error("getaddrinfo() error in connect()!?")
                        continue
                    except socket.error, e:
                        log.error("connect() error: %s", e.strerror)
                        continue
                    source_ip, source_port = sock.getsockname()

                    # Initiate bookkeeping for this stream, tracking it
                    # by source port, useful when we only have a socket as reference.
                    # When we receive a STREAM NEW event, we will also keep
                    # track of it by the STREAM id returned by Tor.
                    stream = Stream()
                    stream.socket = sock
                    stream.router = router
                    stream.source_port = source_port
                    with self.streams_lock:
                        self.streams_by_source[source_port] = stream

                    # Add pending socket and notify stream manager that
                    # we're ready to complete the SOCKS4 handshake.
                    with self.send_pending_cond:
                        self.send_sockets_pending.add(sock)
                        self.send_pending_cond.notify()
            
        elif event.status == "FAILED":
            with self.pending_circuit_cond:
                if self.circuits.has_key(id):
                    log.debug("Established test circuit %d failed: %s", id, event.reason)
                    router = self.circuits[id]
                    router.circuit_failures += 1
                    router.guard.guard_failures += 1
                    self.test_cleanup(router)
                    del self.circuits[id]

                # Circuit failed without being built.
                # Delete from pending_circuits and notify
                # CircuitBuilder that the pending_circuits dict
                # has changed.
                elif self.pending_circuits.has_key(id):
                    router = self.pending_circuits[id]
                    if router.down or router.stale:
                        log.debug("%s: down/stale, circuit failed.")
                    elif "BadExit" in router.flags:
                        log.debug("%s: BadExit! circuit failed.")
                    elif len(event.path) >= 1:
                        router.circuit_failures += 1
                        log.debug("Circ failed (1 hop: r:%s remr:%s). %d failures",
                                  event.reason, event.remote_reason,
                                  router.circuit_failures)
                    else:
                        log.debug("Circ failed (no hop: r:%s remr:%s). Bad guard?",
                                  event.reason, event.remote_reason)
                        router.guard.guard_failures += 1

                    del self.pending_circuits[id]
                    self.test_cleanup(router)
                    self.pending_circuit_cond.notify()

        elif event.status == "CLOSED":
            with self.pending_circuit_cond:
                if self.circuits.has_key(id):
                    log.log(VERBOSE1, "Closed circuit %d (%s).", id,
                            self.circuits[id].nickname)
                    del self.circuits[id]
                elif self.pending_circuits.has_key(id):
                    # Pending circuit closed before being built (can this happen?)
                    log.debug("Pending circuit closed (%d)?", id)
                    router = self.pending_circuits[id]
                    del self.pending_circuits[id]
                    self.test_cleanup(router)
                    self.pending_circuit_cond.notify()
                
    def or_conn_status_event(self, event):
        ## TODO: Do we need to handle ORCONN events?
        pass

    def stream_status_event(self, event):
        if event.status == "NEW":
            if event.target_host == config.test_host:
                portsep = event.source_addr.rfind(':')
                source_port = int(event.source_addr[portsep+1:])
                # Check if this stream is one of ours (TODO: there's no
                # reason AFAIK that it shouldn't be one we initiated
                # if event.target_host is us).
                try:
                    with self.streams_lock:
                        # Get current Stream object for this source port...
                        stream = self.streams_by_source[source_port]
                        # ...and add it to by_id dict.
                        self.streams_by_id[event.strm_id] = stream

                    router = stream.router
                    log.log(VERBOSE2, "Event (%s, %d): New target stream (sport %d).",
                            router.nickname, event.target_port, source_port)
                except KeyError:
                    log.debug("Stream %s:%d is not ours?",
                              event.target_host, event.target_port)
                    return
                
                try:
                    log.log(VERBOSE1, "Event (%s, %d): Attaching stream %d to circuit %d.",
                            router.nickname, event.target_port,
                            event.strm_id, router.circuit)
                    # And attach.
                    self.conn.attach_stream(event.strm_id, router.circuit)

                except TorCtl.ErrorReply, e:
                    # We can receive "552 Unknown stream" if Tor pukes on the stream
                    # before we actually receive the event and use it.
                    log.error("Event (%s, %d): Error attaching stream!",
                              router.nickname, event.target_port)
                    # DO something!
                # Tor closed on us.
                except TorCtl.TorCtlClosed:
                    return

        elif event.status == "FAILED":
            if event.target_host != config.test_host:
                return
            
            port = event.target_port
            stream = self.stream_fetch(id = event.strm_id)
            router = stream.router
            if port in stream.router.current_test.failed_ports:
                log.debug("failed port %d already recorded", port)
                    
            log.log(VERBOSE1, "Stream %s (port %d) failed for %s (reason %s remote %s).",
                    event.strm_id, port, router.nickname, event.reason,
                    event.remote_reason)
            # Explicitly close and remove failed stream socket.
            self.stream_remove(id = event.strm_id)
            stream.socket.failed = True
            # Add to failed list.
            router.current_test.failed(port)
            if router.current_test.is_complete():
                self.completed_test(router)
            
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

    if os.getuid() == 0:
        user, group = config.user, config.group
        if not user:
            raise c("Running as root: set user to drop privileges.")
        if not group:
            raise c("Running as root: set group to drop privileges.")

        try:
            if type(user) is int:
                u = pwd.getpwuid(user)
            else:
                u = pwd.getpwnam(user)
            config.uid = u.pw_uid
        except KeyError:
            raise c("User '%s' not found." % user)

        try:
            if type(group) is int:
                g = grp.getgrgid(group)
            else:
                g = grp.getgrnam(group)
            config.gid = g.gr_gid
        except KeyError:
            raise c("Group '%s' not found." % group)

def sighandler(signum, frame):
    """ TorBEL signal handler. """
    control = sighandler.controller

    if signum in (signal.SIGINT, signal.SIGTERM):
        log.info("Received SIGINT, closing.")
        control.close()
        sys.exit(0)

    elif signum == signal.SIGHUP:
        log.info("Received SIGHUP, doing nothing.")
    
    elif signum == signal.SIGUSR1:
        log.info("SIGUSR1 received: Updating consensus.")
        control._update_consensus(control.conn.get_network_status())

    elif signum == signal.SIGUSR2:
        log.info("SIGUSR2 received: Statistics!")
        time_running = time.time() - control.tests_started
        log.info("Running for %d days, %d hours, %d minutes.",
                 time_running / (60 * 60 * 24),
                 time_running / (60 * 60),
                 time_running / (60))
        log.info("Completed %d tests.", control.tests_completed)
        with control.consensus_cache_lock:
            failures = filter(lambda r: r.circuit_failures > 0 or \
                                  r.guard_failures > 0,
                              control.router_cache.values())

            for failure in failures:
                log.info("%s : %d/%d e, %d/%d g", failure.idhex,
                         failure.circuit_successes, failure.circuit_failures,
                         failure.guard_successes, failure.guard_failures)

# Modified from the Django code base (django.utils.daemonize).
# Thanks, Django devs!
def daemonize(chdir = ".", umask = 022):
    "Robustly turn into a UNIX daemon, running in chdir."
    # First fork
    try:
        if os.fork() > 0:
            sys.exit(0)     # kill off parent
    except OSError, e:
        sys.stderr.write("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)
    # Obtain a new process group.
    os.setsid()
    # Change current directory.
    os.chdir(chdir)
    # Set default file creation mask.
    os.umask(umask)

    # Second fork
    try:
        if os.fork() > 0:
            os._exit(0)
    except OSError, e:
        sys.stderr.write("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror))
        os._exit(1)

    si = open('/dev/null', 'r')
    #so = open(out_log, 'a+', 0)
    #se = open(err_log, 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(si.fileno(), sys.stdout.fileno())
    os.dup2(si.fileno(), sys.stderr.fileno())
    # Set custom file descriptors so that they get proper buffering.
    #sys.stdout, sys.stderr = so, se

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
        return 1

    if config.daemonize:
        log.info("Daemonizing.  See you!")
        daemonize()

    do_tests = "notests" not in sys.argv
    try:
        control = Controller()
        control.start(tests = do_tests)

        sighandler.controller = control
        signal.signal(signal.SIGINT,  sighandler)
        signal.signal(signal.SIGTERM, sighandler)
        signal.signal(signal.SIGHUP,  sighandler)
        signal.signal(signal.SIGUSR1, sighandler)
        signal.signal(signal.SIGUSR2, sighandler)

    except socket.error, e:
        if "Connection refused" in e.args:
            log.error("Connection refused! Is Tor control port available?")

        log.error("Socket error, aborting (%s).", e.args)
        return 1

    except TorCtl.ErrorReply, e:
        log.error("Connection failed: %s", str(e))
        return 2

    # Sleep this thread (for now) while events come in on a separate
    # thread.  Close on SIGINT.
    try:
        while True:
            time.sleep(10)
            if control.is_testing_enabled() and not control.tests_running():
                log.error("Testing has failed.  Aborting.")
                control.close()
                sys.exit(1)

    except KeyboardInterrupt:
        log.info("Received SIGINT, shutting down.")
        control.close()

    return 0

if __name__ == "__main__":
    def usage():
        print "Usage: %s [torhost [ctlport]]" % sys.argv[0]
        sys.exit(1)

    threading.currentThread().name = "Main"
    sys.exit(torbel_start())
