# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.

# Active test scheduler and circuit manager for TorBEL.

# We come from the __future__.
from __future__ import with_statement

import time
import random
import resource
import threading
from copy import copy
from collections import deque

from torbel import config
from torbel.controller import reactor
from torbel.logger import *
log = get_logger("torbel")

class TestScheduler:
    """ Abstract base class for all test schedulers. """
    controller = None
    name = "Abstract"
    def __init__(self, controller, max_pending_factor = 0.5):
        self.controller = controller
        self.terminated = False
        ## Circuit dictionaries.
        # Established circuits under test.
        self.circuits = {}
        # Circuits in the process of being built.
        self.pending_circuits = {}
        self.pending_circuit_lock = threading.RLock()
        self.pending_circuit_cond = threading.Condition(self.pending_circuit_lock)
        # Circuit failure metrics and bookkeeping.
        self.retry_routers = set()
        self.circuit_fail_count = 0
        self.circuit_retry_success_count = 0
        
        # Base max running circuits on the total number of file descriptors
        # we can have open (hard limit returned by getrlimit) and the maximum
        # number of file descriptors per circuit, adjusting for possible pending
        # circuits, TorCtl connection, stdin/out, and other files.
        max_files = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
            
        circuit_limit = max_files / len(controller.test_ports)
        self.max_running_circuits = min(config.max_built_circuits, circuit_limit)
        self.max_pending_circuits = int(self.max_running_circuits * max_pending_factor)

        self.init()

    def init(self):
        """ Initialization routine for a custom scheduler.  Don't override
        __init__. """
        pass
    
    def next(self):
        """ Return a set of routers to be tested. May block until enough routers
        are deemed ready by the scheduler. """

        log.verbose2("Request more circuits. (%d pending, %d running).",
                     len(self.pending_circuits),
                     len(self.circuits))

        with self.pending_circuit_cond:
            # Block until we have less than ten circuits built or
            # waiting to be built.
            while len(self.pending_circuits) >= self.max_pending_circuits or \
                    len(self.circuits) >= self.max_running_circuits:
                self.pending_circuit_cond.wait(3.0)

                # We're done here.
                if self.terminated:
                    return []

        # Get what the child scheduler class wants to test.
        return list(self.fetch_next_tests())

    def new_consensus(self, cache):
        """ Called when a NEWCONSENSUS event occurs. cache is a dictionary
        of the entire consensus, keyed by router ID hash. """
        pass

    def new_descriptor(self, router):
        """ Called when a NEWDESC event occurs. router is the new descriptor
        RouterRecord object. """
        pass
    
    def fetch_next_tests(self):
        """ Scheduler-specific interface that returns a list of
        routers to retry and test.  TestScheduler.next() takes these
        results and performs rate-limiting, so it may not always test
        every router returned by this method.

        Return value is of the form (new_tests, retry_tests), where
        retry_tests is a list of routers that recently failed
        unexpectedly and should be tested again.
        """ 
        raise ValueError("You must implement fetch_next_tests()!")

    def retry_soon(self, router):
        """ Inidcate to the scheduler that the controller was not able
        to complete a stream test or circuit to router, but the result
        may indicate a temporary failure.  The scheduler should retry
        all tests to router as soon as possible."""
        self.retry_routers.add(router)

    def retry_later(self, router):
        """ Indicate to the scheduler that the controller was not able to
        complete a stream test due to a possibly temporary failure, and that
        it should retry at a longer interval than retry_soon. """
        # Default behavior is to use the retry_soon behavior unless
        # implemented otherwise.
        self.retry_soon(self, router)

    def stop(self):
        """ Stop the scheduler. """
        with self.pending_circuit_cond:
            self.pending_circuit_cond.notify()
            self.terminated = True

    def circ_pending(self, circ_id, router):
        with self.pending_circuit_lock:
            self.pending_circuits[circ_id] = router

    def circ_built(self, event):
        circ_id = event.circ_id
        with self.pending_circuit_cond:
            if circ_id in self.pending_circuits:
                router = self.pending_circuits[circ_id]
                del self.pending_circuits[circ_id]
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
                log.verbose1("Retry for %s successful after %d failures (%d/%d %.2f%%)!",
                             router.nickname, router.circuit_failures,
                             self.circuit_retry_success_count,
                             self.circuit_fail_count + self.circuit_retry_success_count,
                             100 * float(self.circuit_retry_success_count) / \
                                 (self.circuit_fail_count + self.circuit_retry_success_count))
            router.circuit_failures = 0

            log.verbose1("Successfully built circuit %d for %s.",
                         circ_id, router.nickname)
            self.circuits[circ_id] = router
            self.controller.connect_test(router)

    def circ_closed(self, event):
        circ_id = event.circ_id
        with self.pending_circuit_cond:
            if circ_id in self.circuits:
                router = self.circuits[circ_id]
                # FINISHED = "The circuit has expired for being dirty or old."
                # (tor-spec.txt 5.4, "Tearing down circuits"). Treat this as
                # an error condition if we have not yet completed the test.
                if event.reason == "FINISHED":
                    if router.current_test and router.current_test.circ_id == circ_id:
                        self.circ_failed(event)
                        return

                log.verbose2("Closed circuit %d (%s).", circ_id,
                             self.circuits[circ_id].nickname)
                del self.circuits[circ_id]

            elif circ_id in self.pending_circuits:
                # Pending circuit closed before being built (can this happen?)
                log.debug("Pending circuit closed (%d)?", circ_id)
                router = self.pending_circuits[circ_id]
                del self.pending_circuits[circ_id]
                # Not technically an explicit failure, but the circuit is already
                # closed, so don't bother doing it again.
                self.controller.test_cleanup(router, circ_failed = True)
                self.pending_circuit_cond.notify()

    def circ_failed(self, event):
        circ_id = event.circ_id
        retry = False

        # We sometimes get a CIRC FAILED event after calling close_circuit,
        # so we should probably ignore these messages to make sure we don't
        # go in circles retrying the circuit build.
        if event.reason == "REQUESTED":
            return

        def cleanup_and_notify(router, retry = False):
            # Cleanup test results and notify the circuit thread.
            self.controller.test_cleanup(router, circ_failed = True)
            self.pending_circuit_cond.notify()
                
            if retry:
                # Append this router to our failure list, and let the scheduler
                # decide if testing should be re-tried.
                self.retry_soon(router)

        with self.pending_circuit_cond:
            if circ_id in self.circuits:
                log.debug("Established test circuit %d failed: %s", circ_id, event.reason)
                router = self.circuits[circ_id]
                router.circuit_failures += 1
                del self.circuits[circ_id]
                cleanup_and_notify(router, retry = True)
                
            elif circ_id in self.pending_circuits:
                # Circuit failed without being built.
                # Delete from pending_circuits and notify
                # CircuitBuilder that the pending_circuits dict
                # has changed.
                self.circuit_fail_count += 1
                router = self.pending_circuits[circ_id]
                if len(event.path) >= 1:
                    router.circuit_failures += 1
                    log.verbose1("Circ to %s failed (r:%s remr:%s). %d failures",
                                 router.nickname, event.reason, event.remote_reason,
                                 router.circuit_failures)
                else:
                    # We failed to extend to the entry guard.  This more than
                    # likely means we have a bad guard.  Remove this guard.
                    log.debug("Bad guard: circuit to %s failed (reason %s).",
                              router.nickname, event.reason)
                    if router.guard:
                        self.controller.remove_guard(router.guard)

                # Remove from pending circuits.
                del self.pending_circuits[circ_id]
                cleanup_and_notify(router, retry = True)

    def retry_candidates(self):
        """ Return a list of circuits that have recently failed and are candidates
        for retrying the test. """
        control = self.controller
        with self.pending_circuit_lock:
            max_retry = min(self.max_pending_circuits / 2,
                            len(self.retry_routers))

            # Look through the circuit failure queue and determine
            # which should be retried and which should wait until the next
            # run-through of testing.
            retry_set = set()
            retry_not_ready = []
            while len(retry_set) < max_retry and len(self.retry_routers) > 0:
                router = self.retry_routers.pop()
                if router.circuit_failures >= 3:
                    log.debug("%s: Too many failures.", router.nickname)
                elif router.is_ready():
                    retry_set.add(router)
                    router.retry = True
                # If a router is not ready to be retried (currently under test),
                # put it back on the retry list.
                else:
                    retry_not_ready.append(router)

            for router in retry_not_ready:
                self.retry_routers.add(router)

        return retry_set

    def print_stats(self):
        pass

class HammerScheduler(TestScheduler):
    """ The Hammer test scheduler hath no mercy. This scheduler will
    continually test every router it knows about.  Very good for
    stress-testing torbel and the Tor network itself, bad in practice."""
    name = "HAMMER"

    def fetch_next_tests(self):
        control = self.controller

        retry = self.retry_candidates()

        # Filter testable routers and sort them by the time their last test
        # started.
        with self.controller.consensus_cache_lock:
            ready = sorted(filter(lambda router: router.is_ready(),
                                  self.controller.router_cache.values()),
                           key = lambda r: r.last_test.start_time)

        # Only return up to self.max_pending_circuits routers to test.
        available_pending = self.max_pending_circuits - len(self.pending_circuits)
        return set(ready[:(available_pending - len(retry_list))]) | retry

class ConservativeScheduler(TestScheduler):
    """ Implement meeee! """
    name = "Conservative"
    def init(self):
        self.router_list = deque()
        self.n = 0
        self.new_router_lock = threading.RLock()
        self.new_router_cond = threading.Condition(self.new_router_lock)

    def new_consensus(self, cache):
        # Add NEWCONSENSUS data to our test cache.
        # TODO: This will cause lots of duplicate tests if we get a NEWCONSENSUS
        # soon after starting TorBEL, but it really shouldn't be a problem with
        # how fast we test.
        cache_values = copy(cache.values())
        random.shuffle(cache_values)
        with self.new_router_cond:
            for router in cache_values:
                self.router_list.append(router)

            self.new_router_cond.notify()

    def new_descriptor(self, router):
        # Append new descriptor to our list and notify a (possibly)
        # sleeping fetch_next_tests.
        with self.new_router_cond:
            self.router_list.append(router)
            self.new_router_cond.notify()

    def retry_soon(self, router):
        # Call parent class and notify possibly sleeping fetch_next_tests
        # call to get things rolling again.
        TestScheduler.retry_soon(self, router)
        with self.new_router_cond:
            self.new_router_cond.notify()

    def fetch_next_tests(self):
        testable = 0

        with self.new_router_cond:
            # Only return up to self.max_pending_circuits routers to test.
            while not self.terminated and testable == 0:
                # Boom, bail.
                if self.terminated:
                    return
                # Start with our retry candidates.
                test_set = self.retry_candidates()
                # Grab the number of available test circuits...
                with self.pending_circuit_lock:
                    available = self.max_pending_circuits - len(self.pending_circuits) - len(test_set)
                # If we have available circuits, grab as many routers to test as
                # possible.
                if available > 0:
                    for i in range(min(len(self.router_list), available)):
                        candidate = self.router_list.popleft()
                        test_set.add(candidate)
                # If we don't have any routers to test, sleep until we are
                # notified of new routers.
                testable = len(test_set)
                if testable == 0:
                    self.new_router_cond.wait()

        # General debugging stats for our test schedule progress.
        with self.controller.consensus_cache_lock:
            router_count = len(self.controller.router_cache)

        if self.n % 30 == 0:
            log.debug("Going to test %d routers. %.1f%% started (%d circs)!",
                      len(test_set),
                      100 * (router_count - len(self.router_list)) / float(router_count),
                      len(self.circuits))
        self.n += 1

        return sorted(list(test_set), key = lambda r: r.last_test.end_time)

    def retry_later(self, router):
        def retry():
            log.debug("Retrying %s(%s)", router.nickname, router.idhex)
            self.retry_soon(router)
        reactor.callLater(5 * 60, retry)

    def print_stats(self):
        TestScheduler.print_stats(self)

    def stop(self):
        # Notify new_router_cond first.
        TestScheduler.stop(self)
        with self.new_router_cond:
            self.new_router_cond.notify()
