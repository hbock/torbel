# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.

# Active test scheduler and circuit manager for TorBEL.

# We come from the __future__.
from __future__ import with_statement

import time
import resource
import threading
from collections import deque
from torbel import config
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
        self.circuit_failures = deque()
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
        
    def next(self):
        """ Return a set of routers to be tested. May block until enough routers
        are deemed ready by the scheduler. """

        #log.debug("Request more circuits. (%d pending, %d running).",
        #          len(self.pending_circuits),
        #          len(self.circuits))

        with self.pending_circuit_cond:
            # Block until we have less than ten circuits built or
            # waiting to be built.
            while len(self.pending_circuits) >= self.max_pending_circuits or \
                    len(self.circuits) >= self.max_running_circuits:
                self.pending_circuit_cond.wait(3.0)

                # We're done here.
                if self.terminated:
                    return []

                #if len(self.circuits) >= self.max_running_circuits:
                #    log.debug("Too many circuits! Cleaning up possible dead circs.")
                #    self.close_old_circuits(60 * 5)

        # Get what the child scheduler class wants to test and retry.
        (new_list, retry_list) = self.fetch_next_tests()
        # Only return up to self.max_pending_circuits routers to test.
        available_pending = self.max_pending_circuits - len(self.pending_circuits)
        return retry_list + new_list[:(available_pending - len(retry_list))]

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
                log.debug("Retry for %s successful after %d failures (%d/%d %.2f%%)!",
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
                log.verbose1("Closed circuit %d (%s).", circ_id,
                             self.circuits[circ_id].nickname)
                del self.circuits[circ_id]
            elif circ_id in self.pending_circuits:
                # Pending circuit closed before being built (can this happen?)
                log.debug("Pending circuit closed (%d)?", circ_id)
                router = self.pending_circuits[circ_id]
                del self.pending_circuits[circ_id]
                self.controller.test_cleanup(router)
                self.pending_circuit_cond.notify()

    def circ_failed(self, event):
        circ_id = event.circ_id

        with self.pending_circuit_cond:
            if circ_id in self.circuits:
                log.debug("Established test circuit %d failed: %s", circ_id, event.reason)
                router = self.circuits[circ_id]
                router.circuit_failures += 1
                router.guard.guard_failures += 1
                self.controller.test_cleanup(router)
                del self.circuits[circ_id]

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
                    self.controller.remove_guard(router.guard)
                
                # Append this router to our failure list, and let the scheduler
                # decide if testing should be re-tried.
                self.circuit_failures.append(router)
                # Remove from pending circuits.
                del self.pending_circuits[circ_id]
                # Cleanup test results and notify the circuit thread.
                self.controller.test_cleanup(router)
                self.pending_circuit_cond.notify()

    def retry_candidates(self):
        """ Return a list of circuits that have recently failed and are candidates
        for retrying the test. """
        control = self.controller
        with self.pending_circuit_lock:
            max_retry = min(self.max_pending_circuits / 2,
                            len(self.circuit_failures))

            # Look through the circuit failure queue and determine
            # which should be retried and which should wait until the next
            # run-through of testing.
            retry_list = []
            while len(retry_list) < max_retry and \
                    len(self.circuit_failures) > 0:
                router = self.circuit_failures.popleft()

                if router.circuit_failures >= 3:
                    log.debug("%s: Too many failures.", router.nickname)

                if router.circuit_failures < 3:
                    retry_list.append(router)
                    router.retry = True

        return retry_list

    def close_old_circuits(self, oldest_time):
        """ Close all built circuits older than oldest_time, given in seconds. """
        ctime = time.time()
        control = self.controller
        with self.pending_circuit_lock:
            for idhex, router in self.circuits.iteritems():
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
    """ The Hammer test scheduler hath no mercy. This scheduler will
    continually test every router it knows about.  Very good for
    stress-testing torbel and the Tor network itself, bad in practice."""
    name = "HAMMER"

    def fetch_next_tests(self):
        control = self.controller

        retry_list = self.retry_candidates()

        # Filter testable routers and sort them by the time their last test
        # started.
        with self.controller.consensus_cache_lock:
            ready = sorted(filter(lambda router: router.is_ready(),
                                  self.controller.router_cache.values()),
                           key = lambda r: r.last_test.start_time)

        return (ready, retry_list)

class ConservativeScheduler(TestScheduler):
    """ Implement meeee! """
    name = "Conservative"
    def fetch_next_tests(self):
        pass
