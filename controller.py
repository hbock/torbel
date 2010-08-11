# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.

# We come from the __future__.
from __future__ import with_statement

import sys, os, pwd, grp, resource
import socket, errno
import threading
import random
import time
import gzip
import csv
from operator import attrgetter

if sys.version_info >= (2,6):
    import json
    
# TODO: Choose the best reactor for the platform.
from twisted.internet import epollreactor
epollreactor.install()
from twisted.internet import reactor

from TorCtl import TorCtl, TorUtil
# torbel submodules
from torbel import scheduler, network
from torbel.logger import *
from torbel.router import RouterRecord

try:
    import config
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

# Change out TorCtl.Router for our own, API-compatible class with
# whizbang features.
TorCtl.Router = RouterRecord

class Stream:
    def __init__(self):
        self.router      = None
        self.strm_id     = None
        self.circ_id     = None
        self.source_port = None
        self.detached_count = 0
        self.state = None

    def setState(self, state):
        #log.debug("stream %d state %s->%s", self.strm_id if self.strm_id else 0,
        #          self.state, state)
        self.state = state

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
        # Test scheduler.
        self.scheduler = None
        # Lock controlling access to the consensus caches.
        self.consensus_cache_lock = threading.Lock()
        # test_ports should never be changed during the lifetime of the program
        # directly.  On SIGHUP test_ports may be changed in its entirety, but
        # ports may not be added or removed by any other method.
        self.test_ports = frozenset(config.test_port_list)
        # Stream data lookup.
        self.streams_by_source = {}
        self.streams_by_id = {}
        self.streams_lock = threading.Lock()

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
        # Also disable WarnUnsafeSocks, as we don't care and don't want to
        # spam the logs with tens of thousands of warnings.
        try:
            self.conn.set_option("LearnCircuitBuildTimeout", "0")
            self.conn.set_option("WarnUnsafeSocks", "0")
            log.debug("Circuit build time learning disabled.")
        except TorCtl.ErrorReply, e:
            log.verbose1("LearnCircuitBuildTimeout not available.  No problem.")

    def init_tests(self):
        """ Initialize testing infrastructure - sockets, resource limits, etc. """
        # Init Twisted factory.
        self.server_factory = network.TestServerFactory(controller = self)
        #self.client_factory = TestClientFactory(controller = self)

        ports = sorted(self.test_ports)
        log.notice("Binding to test ports: %s", ", ".join(map(str, ports)))
        # Sort to try privileged ports first, since sets have no
        # guaranteed ordering.
        for port in ports:
            reactor.listenTCP(port, self.server_factory)

        # Set RLIMIT_NOFILE to its hard limit; we want to be able to
        # use as many file descriptors as the system will allow.
        # NOTE: Your soft/hard limits are inherited from the root user!
        # The root user does NOT always have unlimited file descriptors.
        # Take this into account when editing /etc/security/limits.conf.
        (soft, hard) = resource.getrlimit(resource.RLIMIT_NOFILE)
        log.verbose1("RLIMIT_NOFILE: soft = %d, hard = %d", soft, hard) 
        if soft < hard:
            log.debug("Increasing RLIMIT_NOFILE soft limit to %d.", hard)
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))                

        log.debug("Initializing test threads.")
        # TODO: Configure me!
        scheduler_class = getattr(scheduler, config.scheduler)
        self.scheduler = scheduler_class(controller = self,
                                         max_pending_factor = config.max_pending_factor,
                                         export_interval = config.export_interval)
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
        log.notice("Connected to running Tor instance (version %s) on %s:%d",
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

        if os.getuid() == 0:
            if config.log_file:
                # chown TorUtil plog() logfile, if available.
                if not hasattr(TorUtil, "plog_use_logger") and TorUtil.logfile:
                    os.chown(TorUtil.logfile.name, config.uid, config.gid)
                # chown our logfile so it doesn't stay owned by root.
                os.chown(config.log_file, config.uid, config.gid)
                log.debug("Changed owner of log files to uid=%d, gid=%d",
                          config.uid, config.gid)

            os.setgid(config.gid)
            os.setuid(config.uid)
            log.notice("Dropped root privileges to uid=%d, gid=%d",
                       config.uid, config.gid) 
                
        self.conn = conn
        if config.torctl_debug:
            self.conn.debug(open(config.torctl_debug_file, "w+"))

        self.init_tor()

        ## If the user has not configured test_host, use Tor's
        ## best guess at our external IP address.
        if not config.test_host:
            config.test_host = conn.get_info("address")["address"]

        log.notice("Our external test IP address should be %s.", config.test_host)
            
        # Build a list of Guard routers, so we have a list of reliable
        # first hops for our test circuits.
        log.info("Building router and guard caches from NetworkStatus documents.")
        self._update_consensus(self.conn.get_network_status())

        with self.consensus_cache_lock:
            log.notice("Tracking %d routers, %d of which are guards.",
                       len(self.router_cache), len(self.guard_cache))

        # Initial export without test results.
        self.export_csv()
        if sys.version_info >= (2, 6):
            self.export_json()

        # Finally start testing.
        if self.tests_enabled:
            self.run_tests()

    def build_test_circuit(self, exit):
        """ Build a test circuit using exit and its associated guard node.
            Fail if exit.guard is not set. """
        if not exit.guard:
            raise ValueError("Guard not set for exit %s (%s).", exit.nickname, exit.idhex)

        hops = map(lambda r: "$" + r.idhex, [exit.guard, exit])
        return self.conn.extend_circuit(0, hops)

    def connect_test(self, router):
        def socksConnect(router, port):
            f = network.TestClientFactory((config.test_host, port),
                                          router, controller = self)
            reactor.connectTCP(config.tor_host, config.tor_port, f)
            return f.connectDeferred
                    
        for port in router.current_test.test_ports:
            # Initiate bookkeeping for this stream, tracking it
            # by source port, useful when we only have a socket as reference.
            # When we receive a STREAM NEW event, we will also keep
            # track of it by the STREAM id returned by Tor.
            def connectCallback(sport):
                stream = Stream()
                stream.router = router
                stream.source_port = sport
                stream.circ_id = router.current_test.circ_id
                with self.streams_lock:
                    if sport in self.streams_by_source:
                        s = self.streams_by_source[sport]
                        log.error("Badness: new stream with sport %d already here. old state = %s", sport, s.state)
                    self.streams_by_source[sport] = stream
                        
            def closeCallback(sport):
                self.stream_remove(source_port = sport)
                    
            connect = socksConnect(router, port)
            connect.addCallback(connectCallback)

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
        router.new_test(config.test_port_list, cid)
        router.current_test.start()
        self.scheduler.circ_pending(cid, router)
        
    def end_test(self, router):
        """ Close test circuit associated with router.  Restore
            associated guard to guard_cache. """
        router.circuit_successes += 1
        router.guard.guard_successes += 1
        self.test_cleanup(router)
        self.tests_completed += 1

        test = router.last_test
        def test_done_debug(level):
            log.log(level, "Test %d done [%.1f/min]: %s: %d passed, %d failed.",
                    self.tests_completed,
                    self.tests_completed / ((time.time() - self.tests_started) / 60.0),
                    router.nickname, len(test.working_ports), len(test.failed_ports))
            
        if self.tests_completed % 50 == 0:
            test_done_debug(INFO)
        else:
            test_done_debug(DEBUG)

    def passed(self, router, port):
        """ Mark port as working for router's current test, and end the test if
        it is complete. """
        router.current_test.passed(port)
        if router.current_test.is_complete():
            self.end_test(router)

    def failed(self, router, port):
        """ Mark port as failed for router's current test, and end the test if
        it is complete. """
        if router.current_test:
            router.current_test.failed(port)
            if router.current_test.is_complete():
                self.end_test(router)
        
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
                    sport = stream.source_port
                    if sport and sport in self.streams_by_source:
                        del self.streams_by_source[sport]

            return stream
        
    def test_cleanup(self, router, circ_failed = False):
        """ Clean up router after test - close circuit (if built), return
            circuit entry guard to cache, and return router to guard_cache if
            it is also a guard. """
        # Finish the current test and unset the router guard.
        test = router.end_current_test()
        if test:
            test.circ_failed = circ_failed
            
        router.guard = None

        # If circuit was built for this router, close it.
        # If we get here due to a circuit failure, don't try to close.
        if not circ_failed and test.circ_id:
            try:
                self.conn.close_circuit(test.circ_id, reason = "Test complete")
            except TorCtl.ErrorReply, e:
                msg = e.args[0]
                if "Unknown circuit" in msg:
                    pass
                else:
                    # Re-raise unhandled errors.
                    raise e
            except TorCtl.TorCtlClosed:
                # We don't care. Just bail.
                return

    def test_schedule_thread(self):
        log.debug("Starting test schedule thread.")

        log.notice("Initialized %s test scheduler.", self.scheduler.name)
        self.scheduler.start()
        while not self.terminated:
            test_list = self.scheduler.next()
            for router in test_list:
                self.start_test(router)

        log.debug("Terminating scheduler thread.")

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

    def remove_guard(self, guard):
        """ Remove a guard from our guard cache. """
        with self.consensus_cache_lock:
            try:
                self.guard_cache.remove(guard.idhex)
            except ValueError:
                pass

    def export(self):
        self.export_csv()
        # Native JSON support only available in Python >= 2.6.
        if sys.version_info >= (2, 6):
            self.export_json()

    def export_json(self):
        """ Export current router cache in JSON format.  See data-spec. """
        fn = config.export_file_prefix + (".json.gz" if config.export_gzip else ".json")
        fn_new = fn + ".NEW"
        try:
            if config.export_gzip:
                fd = gzip.open(fn_new, "w")
            else:
                fd = open(fn_new, "w")
            
            with self.consensus_cache_lock:
                records = [router.dump(fd) for router in self.router_cache.values() \
                               if router.should_export()]

            json.dump(records, fd)
            fd.close()

        except IOError, e:
            (errno, strerror) = e
            log.error("I/O error writing to file %s: %s", fn_new, strerror)

        try:
            # rename() is atomic under POSIX.
            # We need an atomic way to update our export file so it can
            # be fetched without worrying about incomplete exports.
            os.rename(fn_new, fn)

        except IOError, e:
            (errno, strerror) = e
            log.error("Atomic rename error: %s to %s failed: %s", fn_new, fn, strerror)
            
    def export_csv(self):
        """ Export current router cache in CSV format.  See data-spec
            for more information on export formats. """
        fn = config.export_file_prefix + (".csv.gz" if config.export_gzip else ".csv")
        fn_new = fn + ".NEW"

        try:
            if config.export_gzip:
                csv_file = gzip.open(fn_new, "w")
            else:
                csv_file = open(fn_new, "w")
                
            out = csv.writer(csv_file, dialect = csv.excel)

            # FIXME: Is it safe to just take the itervalues list?
            with self.consensus_cache_lock:
                for router in self.router_cache.itervalues():
                    if router.should_export():
                        router.export_csv(out)
            
        except IOError, e:
            (errno, strerror) = e
            log.error("I/O error writing to file %s: %s", fn_new, strerror)

        csv_file.close()
        try:
            os.rename(fn_new, fn)
        except IOError, e:
            (errno, strerror) = e
            log.error("Atomic rename error: %s to %s failed: %s", fn_new, fn, strerror)
            
    def close(self):
        """ Close the connection to the Tor control port and end testing.. """
        self.terminated = True
        if self.tests_enabled:
            if self.scheduler:
                self.scheduler.stop()
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
        log.notice("Closing Tor controller connection.")
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
                # Notify scheduler that a new router is available for testing.
                if self.scheduler:
                    self.scheduler.new_descriptor(router)
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
        new_routers = self.conn.read_routers(nslist)
        old_ids = set()

        with self.consensus_cache_lock:
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
            with self.consensus_cache_lock:
                router = self.router_cache[id]
            if router.stale:
                # Check to see if it has been out-of-consensus for long enough to
                # warrant dropping it from our records.
                # NOTE: This is disabled, for now, as the general consensus is
                # to not stop testing routers even if they fall out of the
                # consensus.  We want to know before they come back, if
                # possible.
                cur_time = int(time.time())
                if((cur_time - router.stale_time) > config.stale_router_timeout):
                    pass

            else:
                # Record router has fallen out of the consensus, and when.
                router.stale      = True
                router.stale_time = int(time.time())

        # Rebuild guard cache with new consensus data.
        with self.consensus_cache_lock:
            self.guard_cache = map(lambda guard: guard.idhex,
                                   filter(lambda router: "Guard" in router.flags,
                                          self.router_cache.itervalues()))

        if self.scheduler:
            self.scheduler.new_consensus(self.router_cache)

    def new_consensus_event(self, event):
        log.debug("Received NEWCONSENSUS event.")
        self._update_consensus(event.nslist)
        
    def circ_status_event(self, event):
        # If we restart TorBEL when Tor was still constructing circuits,
        # we may get residual events from circuits in the previous run.
        # Ignore them until we have a scheduler.
        if not self.scheduler:
            return

        if event.status == "BUILT":
            self.scheduler.circ_built(event)

        elif event.status == "FAILED":
            self.scheduler.circ_failed(event)

        elif event.status == "CLOSED":
            self.scheduler.circ_closed(event)
                
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
                        stream.setState("NEW")
                        if stream.strm_id:
                            log.error("WTF already has a straem id?")
                        stream.strm_id = event.strm_id
                        # ...and add it to by_id dict.
                        self.streams_by_id[event.strm_id] = stream

                    router = stream.router
                    log.verbose2("(%s, %d): New target stream (sport %d).",
                                 router.nickname, event.target_port, source_port)

                except KeyError:
                    log.debug("Stream %d(port %d) is not ours?",
                              event.strm_id, event.target_port)
                    return
                
                try:
                    log.verbose2("(%s, %d): Attaching stream %d to circuit %d.",
                                 router.nickname, event.target_port,
                                 event.strm_id, router.current_test.circ_id)
                    self.conn.attach_stream(event.strm_id, router.current_test.circ_id)

                except TorCtl.ErrorReply, e:
                    # We can receive "552 Unknown stream" if Tor pukes on the stream
                    # before we actually receive the event and use it.
                    log.error("(%s, %d): Error attaching stream!",
                              router.nickname, event.target_port)
                    # DO something!

                # Tor closed on us.
                except TorCtl.TorCtlClosed:
                    return

        elif event.status == "DETACHED":
            # A stream we attached to a circuit has been detached.
            stream = self.stream_fetch(id = event.strm_id)
            stream.setState("DETACHED")
            router = stream.router

            if event.reason == "END":
                fail = True
                # The router is not allowing traffic to this port currently.
                if event.remote_reason == "EXITPOLICY":
                    fail = True
                # This router is hibernating and will not allow traffic.
                elif event.remote_reason == "HIBERNATING":
                    # TODO: Mark as inaccessible.
                    fail = True

                # We err on the side of caution here and assume the router will
                # usually let traffic through on that port if we detach for
                # RESOURCELIMIT/MISC.
                # MISC seems to be unhandled EHOSTUNREACH in some versions of Tor.
                # It is important to re-test this router sooner than other routers
                # to see if we can provide a more definitive answer (if it would in
                # fact fail).
                elif event.remote_reason == "RESOURCELIMIT":
                    log.verbose1("(%s,%d): detached due to resource limit, assuming PASS",
                                 router.nickname, event.target_port)
                    fail = False
                    self.scheduler.retry_later(router)

                elif event.remote_reason == "MISC":
                    # log.critical("(%s(%s),%d): MISC: tor %s os %s",
                    #              router.idhex, router.nickname, event.target_port,
                    #              router.version.ver_string, router.os)
                    self.scheduler.retry_later(router)
                    fail = False

                else:
                    log.debug("(%s,%d): detached due to %s", router.nickname,
                              event.target_port, event.remote_reason)
                    fail = True

                # We have no reason to attempt to re-attach these streams;
                # just close them.
                try:
                    # 7 = REASON_TIMEOUT in tor-spec.txt section 6.3.
                    self.conn.close_stream(event.strm_id, reason = 7)
                except TorCtl.TorCtlClosed:
                    # Bail if we closed.
                    return

                if fail:
                    self.failed(stream.router, event.target_port)
                else:
                    self.passed(stream.router, event.target_port)

                return

            # Catch-all for things I don't currently handle.
            elif event.reason != "TIMEOUT":
                log.debug("%s: Stream %d detached from circuit %d (reason = %s)",
                          router.nickname, event.strm_id, event.circ_id, event.reason)

            # If the reason for detaching isn't END, we try to attach the stream
            # again to the same circuit MAX_DETACH_RETRY times before giving up.
            # If we give up, ask the scheduler to retry the entire test soon.
            MAX_DETACH_RETRY = 3
            if stream.detached_count >= MAX_DETACH_RETRY:
                self.failed(router, event.target_port)
                self.scheduler.retry_later(router)
                return

            stream.detached_count += 1

            # FIXME: It seems like we never hit this, and I shouldn't be
            # accessing scheduler.circuits.
            if stream.circ_id not in self.scheduler.circuits:
                log.debug("%s: can't reattach stream to dead circ %d",
                          router.nickname, stream.circ_id)
                return

            # If we reach this point, we likely hit a DETACH reason that
            # is retriable.  Retry attaching the stream.
            try:
                log.verbose2("%s: Retrying stream %s to circ %s",
                             router.nickname, str(event.strm_id), str(stream.circ_id))
                self.conn.attach_stream(stream.strm_id, stream.circ_id)
            # If Tor barfs, the circuit was probably closed before we could
            # handle the DETACH event.  Fail the port temporarily, and ask
            # scheduler to retry ASAP.
            except TorCtl.ErrorReply, e:
                self.failed(router, event.target_port)
                self.scheduler.retry_later(router)
            # Ignore closed notification.
            except TorCtl.TorCtlClosed:
                return

        elif event.status == "CLOSED":
            try:
                stream = self.stream_remove(id = event.strm_id)
                stream.setState("CLOSED")
                self.stream_remove(source_port = stream.source_port)
            except KeyError:
                # Streams not in the by_id dict
                pass
            
        elif event.status == "FAILED":
            if event.target_host != config.test_host:
                return
           
            port = event.target_port
            # We are unable to find the corresponding stream in our
            # own bookkeeping if we didn't know about the stream in
            # the NEW event either.

            # TODO: This is possibly a bug if the connectDeferred defer
            # object is never called back, causing us not to record
            # the source port of a stream we have originated.
            try:
                stream = self.stream_fetch(id = event.strm_id)
            except KeyError:
                log.debug("Stream %d(port %d) failed, not known to us. Ignored.",
                          event.strm_id, event.target_port)
                return

            stream.setState("FAILED")
            router = stream.router

            # From what I can tell, we only get STREAM x FAILED 0 if
            # the circuit was truncated after being built - I've only seen
            # FAILED 0 after a circuit was CLOSED REASON=FINISHED, where
            # finished is "The circuit has expired for being dirty or old."
            # In this case, our current_test is already closed and we should
            # simply discard the stream data and give up.
            if event.circ_id == 0:
                self.stream_remove(id = event.strm_id)
                return

            # If current_test is None, we may have a problem. Still trying to debug.
            if not router.current_test:
                # If we receive a FAILED event for a stream for an old test,
                # ignore it.  We shouldn't do anything about it now.
                if event.circ_id < router.last_test.circ_id:
                    pass

                # Okay, this is where we need more insight.  Give some information
                # about the event stream ID, circuit ID, and last test times
                # and circuit ids, and what ports we got results for.
                else:
                    log.debug("%s(p%d,s%d,c%d): no current_test? last %d:%d circ_id %d passed %s failed %s",
                              router.nickname, port, event.strm_id, event.circ_id,
                              router.last_test.start_time,
                              router.last_test.end_time,
                              router.last_test.circ_id,
                              router.last_test.working_ports,
                              router.last_test.failed_ports)

            elif event.circ_id != router.current_test.circ_id:
                log.critical("%s: fail event for stream %d(c%d), expected %s",
                             router.nickname, event.strm_id, event.circ_id,
                             router.current_test.circ_id)
                return

            elif port in router.current_test.failed_ports:
                log.debug("%s: failed port %d already recorded", router.nickname, port)

            # If we get this far, it's likely the stream actually failed, so log
            # why and handle it.
            log.verbose1("Stream %s (port %d) failed for %s (reason %s remote %s).",
                         event.strm_id, port, router.nickname, event.reason,
                         event.remote_reason)

            # Remove stream from our bookkeeping.
            self.stream_remove(id = event.strm_id)

            # Add to failed list.
            self.failed(router, port)

        else:
            stream = self.stream_fetch(id = event.strm_id)
            stream.setState(event.status)
