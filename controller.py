#!/usr/bin/python
# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.

# We come from the __future__.
from __future__ import with_statement

import sys, os, pwd, grp, resource
import socket, struct, errno
import threading
import random, time
import csv
from collections import deque
from operator import attrgetter

from twisted.internet.protocol import Protocol, Factory, ClientFactory
# TODO: Choose the best reactor for the platform.
from twisted.internet import epollreactor
epollreactor.install()
from twisted.internet import reactor, defer
from twisted.internet import error as twerror

from TorCtl import TorCtl, TorUtil
# torbel submodules
from logger import *

try:
    import torbel_config as config
except ImportError:
    sys.stderr.write("Error: Could not load config file (torbel_config.py)!\n")
    sys.exit(1)

log = create_logger("torbel",
                    level  = config.log_level,
                    torctl_level = config.torctl_log_level,
                    syslog = config.log_syslog,
                    stdout = config.log_stdout,
                    file   = config.log_file)

# If using latest TorCtl with my logging patches...
if hasattr(TorUtil, "plog_use_logger"):
    # ...create a TorCtl logger that uses the same formatting and
    # handlers as TorBEL.  This allows us to use the same files
    # and syslog.
    create_logger("TorCtl", level = config.torctl_log_level, 
                  syslog = config.log_syslog,
                  stdout = config.log_stdout,
                  file   = config.log_file)
    TorUtil.plog_use_logger("TorCtl")
# Otherwise set up older TorCtl.
# TODO: Remove this when/if mikeperry accepts logging patches.
else:
    TorUtil.loglevel = torutil_level_mapper[config.torctl_log_level]
    if config.log_file:
        TorUtil.logfile = open(config.log_file + "-TorCtl", "w+")

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
        self.retry = False

    def __eq__(self, other):
        return self.idhex == other.idhex

    def __ne__(self, other):
        return self.idhex != other.idhex

    def is_exit(self):
        return len(self.last_test.test_ports) != 0

    def is_ready(self):
        """ Returns True if this router ready for a new test; that is,
            it is not currently being tested and it is testable. """
        return (not self.current_test and self.last_test.test_ports)
        
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
        self.router      = None
        self.strm_id     = None
        self.circ_id     = None
        self.source_port = None

class TestServer(Protocol):
    def connectionMade(self):
        self.host = self.transport.getHost()
        self.peer = self.transport.getPeer()
        self.data = ""

        log.log(VERBOSE2, "Connection from %s:%d", self.peer.host, self.host.port)

    def dataReceived(self, data):
        self.data += data
        if len(self.data) >= 40:
            self.factory.handleTestData(self.transport, self.data)
            self.transport.loseConnection()

    def connectionLost(self, reason):
        # Ignore clean closes.
        if not reason.check(twerror.ConnectionDone):
            # Ignore errors during shutdown.
            if reason.check(twerror.ConnectionLost) and self.factory.isTerminated():
                return
            log.log(VERBOSE2, "Connection from %s:%d lost: reason %s.",
                    self.peer.host, self.host.port, reason)
        
class TestServerFactory(Factory):
    protocol = TestServer

    def __init__(self, controller):
        self.controller = controller

    def isTerminated(self):
        return self.controller.terminated
    
    def handleTestData(self, transport, data):
        host = transport.getHost()
        peer = transport.getPeer()
        controller = self.controller

        with controller.consensus_cache_lock:
            if data in controller.router_cache:
                router = controller.router_cache[data]
            else:
                router = None

        if router:
            router.current_test.passed(host.port)
            (ip,) = struct.unpack(">I", socket.inet_aton(peer.host))
            router.actual_ip = ip
            
            # TODO: Handle the case where the router exits on
            # multiple differing IP addresses.
            if router.actual_ip and router.actual_ip != ip:
                log.debug("%s: multiple IP addresses, %s and %s (%s advertised)!",
                             router.nickname, ip, router.actual_ip, router.ip)
                
            if router.current_test.is_complete():
                controller.end_test(router)

        else:
            log.debug("Bad data from peer: %s", data)

    def clientConnectionLost(self, connector, reason):
        log.debug("Connection from %s lost, reason %s", connector, reason)
    
    def clientConnectionFailed(self, connector, reason):
        log.debug("Connection from %s failed, reason %s", connector, reason)

class TestClient(Protocol):
    """ Implementation of SOCKS4 and the testing "protocol". """
    SOCKS4_SENT, SOCKS4_REPLY_INCOMPLETE, SOCKS4_CONNECTED, SOCKS4_FAILED = range(4)
    
    def connectionMade(self):
        peer_host, peer_port = self.factory.peer
        self.transport.write("\x04\x01" + struct.pack("!H", peer_port) +
                             socket.inet_aton(peer_host) + "\x00")
        self.state = self.SOCKS4_SENT
        self.data = ""

        # Call the deferred callback with our stream source port.
        self.factory.connectDeferred.callback(self.transport.getHost().port)

    def dataReceived(self, data):
        # We should not receive data unless we just sent the SOCKS4 initial
        # handshake.
        if self.state != self.SOCKS4_SENT:
            log.error("Received data outside SOCKS4_SENT state.")
            self.transport.loseConnection()

        self.data += data
        if len(self.data) < 8:
            self.state = self.SOCKS4_REPLY_INCOMPLETE
        elif len(self.data) == 8:
            (status,) = struct.unpack('xBxxxxxx', self.data)
            # 0x5A == success; 0x5B-5D == failure/rejected
            if status == 0x5A:
                log.log(VERBOSE2, "SOCKS4 connect successful")
                self.state = self.SOCKS4_CONNECTED
                self.transport.write(self.factory.testData())
            else:
                log.log(VERBOSE2, "SOCKS4 connect failed")
                self.state = self.SOCKS4_FAILED
                self.transport.loseConnection()
        else:
            log.error("WTF too many bytes in SOCKS4 connect!")
            self.transport.loseConnection()

class TestClientFactory(ClientFactory):
    protocol = TestClient
    def __init__(self, peer, router):
        self.router = router
        self.peer = peer
        self.connectDeferred = defer.Deferred()

    def testData(self):
        return self.router.idhex

    def clientConnectionLost(self, connector, reason):
        #if not reason.check(twerror.ConnectionDone):
        pass   

    def clientConnectionFailed(self, connector, reason):
        pass

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
        self.guard_cache = []
        # Lock controlling access to the consensus caches.
        self.consensus_cache_lock = threading.RLock()
        # test_ports should never be changed during the lifetime of the program
        # directly.  On SIGHUP test_ports may be changed in its entirety, but
        # ports may not be added or removed by any other method.
        self.test_ports = frozenset(config.test_port_list)
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
        self.circuit_failures = deque()
        self.circuit_fail_count = 0
        self.circuit_retry_success_count = 0

        self.terminated = False
        self.tests_enabled = False
        # Threads
        self.schedule_thread = None
        self.tests_completed = 0
        self.tests_started = 0

    def init_tor(self):
        """ Initialize important Tor options that may not be set in
            the user's torrc. """
        log.debug("Setting Tor options.")
        self.conn.set_option("__LeaveStreamsUnattached", "1")
        # Fetch all descriptors we can get, even ones that are "useless", and do
        # so as early as possible so we can test them and see if they have become
        # active since the last consensus.
        # This allows us to notify torbel clients about new working relays before
        # clients actually try to use them.
        self.conn.set_option("FetchUselessDescriptors", "1")
        self.conn.set_option("FetchDirInfoEarly", "1")
        try:
            self.conn.set_option("FetchDirInfoExtraEarly", "1")
        except TorCtl.ErrorReply:
            log.warn("FetchDirInfoExtraEarly not available; your Tor is too old. Continuing anyway.")
        # We must disable cbt learning to get proper behavior under recent Tor
        # versions (0.2.2.14-alpha).
        try:
            self.conn.set_option("LearnCircuitBuildTimeout", "0")
            log.debug("Circuit build time learning disabled.")
        except TorCtl.ErrorReply:
            log.log(VERBOSE1, "LearnCircuitBuildTimeout not available.  No problem.")

    def init_tests(self):
        """ Initialize testing infrastructure - sockets, resource limits, etc. """
        # Init Twisted factory.
        self.server_factory = TestServerFactory(controller = self)
        #self.client_factory = TestClientFactory(controller = self)

        ports = sorted(self.test_ports)
        log.info("Binding to test ports: %s", ", ".join(map(str, ports)))
        # Sort to try privileged ports first, since sets have no
        # guaranteed ordering.
        for port in ports:
            reactor.listenTCP(port, self.server_factory)
                
        if os.getuid() == 0:
            os.setgid(config.gid)
            os.setuid(config.uid)
            log.info("Dropped root privileges to uid=%d, gid=%d", config.uid, config.gid)

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
        self.schedule_thread = T(target = Controller.test_schedule_thread,
                                 name = "Scheduler", args = (self,))

    def run_tests(self):
        """ Start the test thread. """
        if self.schedule_thread:
            if self.schedule_thread.isAlive():
                log.error("BUG: Circuit thread already running!")
                return
            self.tests_started = time.time()
            self.schedule_thread.start()
            # Start the Twisted reactor.
            reactor.run()
            
        else:
            log.error("BUG: Circuit thread not initialized!")

    def is_testing_enabled(self):
        """ Is testing enabled for this Controller instance? """
        return self.tests_enabled

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
        log.info("Connected to running Tor instance (version %s) on %s:%d",
                 conn.get_info("version")['version'], self.host, self.port)
        ## We're interested in:
        ##   - Circuit events
        ##   - Stream events.
        ##   - Tor connection events.
        ##   - New descriptor events, to keep track of new exit routers.
        ##   - We NEED extended events.
        conn.set_events([TorCtl.EVENT_TYPE.CIRC,
                         TorCtl.EVENT_TYPE.STREAM,
                         TorCtl.EVENT_TYPE.ORCONN,
                         TorCtl.EVENT_TYPE.NEWDESC,
                         TorCtl.EVENT_TYPE.NEWCONSENSUS], extended = True)
        self.conn = conn
        if config.torctl_debug:
            self.conn.debug(open(config.torctl_debug_file, "w+"))
 
        self.init_tor()

        ## If the user has not configured test_host, use Tor's
        ## best guess at our external IP address.
        if not config.test_host:
            config.test_host = conn.get_info("address")["address"]

        log.info("Our external test IP address should be %s.", config.test_host)
            
        # Build a list of Guard routers, so we have a list of reliable
        # first hops for our test circuits.
        log.info("Building router and guard caches from NetworkStatus documents.")
        self._update_consensus(self.conn.get_network_status())

        with self.consensus_cache_lock:
            log.info("Tracking %d routers, %d of which are guards.",
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

    def start_test(self, router, retry = False):
        """ Begin active testing for router. """
        with self.consensus_cache_lock:
            # Take random guard out of available guard list,
            # ensuring we don't pick ourselves.
            guard_id = random.choice(self.guard_cache)
            while guard_id == router.idhex:
                guard_id = random.choice(self.guard_cache)
            router.guard = self.router_cache[guard_id]

        # Build test circuit.
        try:
            cid = self.build_test_circuit(router)
        except TorCtl.ErrorReply, e:
            if "551 Couldn't start circuit" in e.args:
                # Tor puked, usually meaning RLIMIT_NOFILE is too low.
                log.error("Tor failed to build circuit due to resource limits.")
                log.error("Please raise your 'nofile' resource hard limit for the Tor and/or root user and restart Tor.  See TorBEL README for more details.")
                # We need to bail.
                return
                        
        # Start test.
        router.new_test()
        router.current_test.start()
        with self.pending_circuit_lock:
            self.pending_circuits[cid] = router

        
    def end_test(self, router):
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
                 self.tests_completed / ((time.time() - self.tests_started) / 60.0),
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
        # Finish the current test and unset the router guard.
        router.end_current_test()
        router.guard = None

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

    class TestScheduler:
        """ Abstract base class for all test schedulers. """
        controller = None
        name = "Abstract"
        def __init__(self, controller, max_pending_circuits = 10):
            self.controller = controller
            self.max_pending_circuits = max_pending_circuits
            # Base max running circuits on the total number of file descriptors
            # we can have open (hard limit returned by getrlimit) and the maximum
            # number of file descriptors per circuit, adjusting for possible pending
            # circuits, TorCtl connection, stdin/out, and other files.
            max_files = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
            
            circuit_limit = max_files / len(controller.test_ports) - max_pending_circuits
            self.max_running_circuits = min(config.max_built_circuits, circuit_limit)

        def next(self):
            """ Return a set of routers to be tested. May block until enough routers
                are deemed ready by the scheduler. """
            raise ValueError("You must implement next()!")

        def stop(self):
            """ Stop the scheduler. """
            pass

        def close_old_circuits(self, oldest_time):
            """ Close all built circuits older than oldest_time, given in seconds. """
            ctime = time.time()
            control = self.controller
            with control.pending_circuit_lock:
                for idhex, router in control.circuits.iteritems():
                    if not router.current_test:
                        continue
                    if (ctime - router.current_test.start_time) > oldest_time:
                        test = router.current_test
                        ndone = len(test.working_ports) + len(test.failed_ports)
                        log.debug("Closing old circuit %d (%s, %d done, %d needed - %s)",
                                  router.circuit, router.nickname, ndone,
                                  len(test.test_ports) - ndone,
                                  router.idhex)
                        control.test_cleanup(router)

    class HammerScheduler(TestScheduler):
        """ The Hammer test scheduler hath no mercy but to save its own hide
            from EMFILE. This scheduler will continually test every router it
            knows about as long as it is not in danger of running out of file
            descriptors. Very good for stress-testing torbel and the Tor network
            itself, bad in practice. """
        name = "HAMMER"
        def __init__(self, controller):
            Controller.TestScheduler.__init__(self, controller)
            
        def next(self):
            control = self.controller
            retry_list = []
            
            with control.pending_circuit_cond:
                # Block until we have less than ten circuits built or
                # waiting to be built.
                # TODO: Make this configurable?
                while len(control.pending_circuits) >= self.max_pending_circuits or \
                        len(control.circuits) >= self.max_running_circuits:
                    control.pending_circuit_cond.wait(3.0)

                    # We're done here.
                    if control.terminated:
                        return []

                    elif len(control.circuits) >= self.max_running_circuits:
                        log.debug("Too many circuits! Cleaning up possible dead circs.")
                        self.close_old_circuits()

                    max_retry = min(self.max_pending_circuits / 2,
                                    len(control.circuit_failures))

                    # Look through the circuit failure queue and determine
                    # which should be retried and which should wait until the next
                    # run-through of testing.
                    while len(retry_list) < max_retry and \
                            len(control.circuit_failures) > 0:
                        router = control.circuit_failures.popleft()

                        # Don't retry a circuit until the next pass if it:
                        #   - Is hibernating (router.down)
                        #   - Has been flagged as a BadExit
                        #   - Has been out of consensus for too long (router.stale)
                        #   - Has failed to be extended to more than twice.
                        # On second thought, this may be bad, since the success rate
                        # for retries is fairly good (~20%) and it doesn't cost much
                        # to retry.
                        # if router.down or router.stale:
                        #     log.debug("%s: down/stale. Not retrying.", router.nickname)
                        # elif "BadExit" in router.flags:
                        #     log.debug("%s: BadExit! Not retrying..", router.nickname)
                        if router.circuit_failures >= 3:
                            log.debug("%s: Too many failures.", router.nickname)
                        else:
                            log.log(VERBOSE1, "Retrying %s.", router.nickname)
                            retry_list.append(router)
                            router.retry = True

            # Filter testable routers and sort them by the time their last test
            # started.
            with control.consensus_cache_lock:
                ready = sorted(filter(lambda router: router.is_ready(),
                                      control.router_cache.values()),
                                      key = lambda r: r.last_test.start_time)
            # Only return up to self.max_pending_circuits routers to test.
            return retry_list + ready[:(self.max_pending_circuits - len(retry_list))]

    class ConservativeScheduler(TestScheduler):
        """ Implement meeee! """
        pass

    def test_schedule_thread(self):
        log.debug("Starting test schedule thread.")

        # TODO: Configure me!
        scheduler = self.HammerScheduler(self)
        log.info("Initialized %s test scheduler.", scheduler.name)
        while not self.terminated:
            log.debug("Request more circuits. (%d pending, %d running).",
                      len(self.pending_circuits),
                      len(self.circuits))
            log.debug("%d:%d streams open",
                      len(self.streams_by_id),
                      len(self.streams_by_source))

            for router in scheduler.next():
                self.start_test(router)

        scheduler.stop()
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
                        self.guard_cache.remove(router.idhex)

            else:
                # Add new record to router_cache.
                self.router_cache[router.idhex] = router
                # Add new record to guard_cache, if appropriate.
                # NOTE: If for some strange reason we get a NEWDESC
                # event for a guard that is already in our guard cache,
                # it will be listed twice.  It's not a problem, since
                # using a guard more often is okay if it is reliable.
                # If it is unreliable it will be removed from the cache
                # anyway.
                if "Guard" in router.flags:
                    self.guard_cache.append(router.idhex)
            
        return True

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
            # Notify any sleeping threads.
            with self.pending_circuit_cond:
                self.pending_circuit_cond.notify()
            log.info("Joining test threads.")
            # Don't try to join a thread if it hasn't been created.
            if self.schedule_thread and self.schedule_thread.isAlive():
                self.schedule_thread.join()
            log.info("All threads joined.")

        log.info("Stopping reactor.")
        # Ensure reactor is running before we try to stop it, otherwise
        # Twisted will raise an exception.
        if reactor.running:
            reactor.stop()
        log.info("Closing Tor controller connection.")
        self.conn.close()

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

            old_ids = set()
            for idhex, router in self.router_cache.iteritems():
                # Populate old_ids...
                old_ids.add(idhex)
                # ...and give the router a clean circuit_failures count.
                # NEWCONSENSUS is like Christmas.
                router.circuit_failures = 0

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
            # Rebuild guard cache with new consensus data.
            self.guard_cache = map(lambda guard: guard.idhex,
                                   filter(lambda router: "Guard" in router.flags,
                                          self.router_cache.itervalues()))

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
                    # Notify scheduler thread that we have
                    # completed building a circuit and we could
                    # need to pre-build more.
                    self.pending_circuit_cond.notify()
                else:
                    return

                # If we succeeded in building this router on retry,
                # reset its failure count to give it a clean slate.
                if router.retry:
                    self.circuit_retry_success_count += 1
                    router.retry = False
                    router.circuit_failures = 0
                    log.debug("Retry for %s successful (%d/%d succesful, %.2f%%)!",
                              router.nickname, self.circuit_retry_success_count,
                              self.circuit_fail_count + self.circuit_retry_success_count,
                              100 * float(self.circuit_retry_success_count) / \
                                  (self.circuit_fail_count + self.circuit_retry_success_count))
                
                log.log(VERBOSE1, "Successfully built circuit %d for %s.",
                        id, router.nickname)
                self.circuits[id] = router
                def socksConnect(router, port):
                    f = TestClientFactory((config.test_host, port), router)
                    reactor.connectTCP(config.tor_host, config.tor_port, f)
                    return f.connectDeferred
                    
                for port in router.exit_ports(config.test_host, config.test_port_list):
                    # Initiate bookkeeping for this stream, tracking it
                    # by source port, useful when we only have a socket as reference.
                    # When we receive a STREAM NEW event, we will also keep
                    # track of it by the STREAM id returned by Tor.
                    def connectCallback(sport):
                        stream = Stream()
                        stream.router = router
                        stream.source_port = sport
                        with self.streams_lock:
                            self.streams_by_source[sport] = stream

                    def closeCallback(sport):
                        self.stream_remove(source_port = sport)
                        
                    connect = socksConnect(router, port)
                    connect.addCallback(connectCallback)

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
                    self.circuit_fail_count += 1
                    router = self.pending_circuits[id]
                    if len(event.path) >= 1:
                        router.circuit_failures += 1
                        log.log(VERBOSE1, "Circ to %s failed (r:%s remr:%s). %d failures",
                                  router.nickname, event.reason, event.remote_reason,
                                  router.circuit_failures)
                    else:
                        # We failed to extend to the entry guard.  This more than
                        # likely means we have a bad guard.  Remove this guard.
                        log.debug("Bad guard: circuit to %s failed (reason %s).",
                                  router.nickname, event.reason)
                        with self.consensus_cache_lock:
                            try:
                                self.guard_cache.remove(router.guard.idhex)
                            except ValueError:
                                pass

                    # Append this router to our failure list, and let the scheduler
                    # decide if testing should be re-tried.
                    self.circuit_failures.append(router)
                    # Remove from pending circuits.
                    del self.pending_circuits[id]
                    # Cleanup test results and notify the circuit thread.
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
        def getSourcePort():
            portsep = event.source_addr.rfind(':')
            return int(event.source_addr[portsep+1:])            

        if event.status == "NEW":
            if event.target_host == config.test_host:
                source_port = getSourcePort()
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
                    log.log(VERBOSE2, "(%s, %d): New target stream (sport %d).",
                            router.nickname, event.target_port, source_port)

                except KeyError:
                    log.debug("Stream %s:%d is not ours?",
                              event.target_host, event.target_port)
                    return
                
                try:
                    log.log(VERBOSE2, "(%s, %d): Attaching stream %d to circuit %d.",
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

        elif event.status == "CLOSED":
            try:
                stream = self.stream_remove(id = event.strm_id)
                self.stream_remove(source_port = stream.source_port)
            except KeyError:
                # Streams not in the by_id dict
                pass
            
        elif event.status == "FAILED":
            if event.target_host != config.test_host:
                return
           
            port = event.target_port
            stream = self.stream_fetch(id = event.strm_id)
            router = stream.router
            if port in stream.router.current_test.failed_ports:
                log.debug("failed port %d already recorded", port)
                    
            log.log(DEBUG, "Stream %s (port %d) failed for %s (reason %s remote %s).",
                    event.strm_id, port, router.nickname, event.reason,
                    event.remote_reason)
            # Explicitly close and remove failed stream socket.
            self.stream_remove(id = event.strm_id)
            # Add to failed list.
            router.current_test.failed(port)
            if router.current_test.is_complete():
                self.end_test(router)
