# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.
import csv
import socket
import struct
import time
from TorCtl import TorCtl

_OldRouterClass = TorCtl.Router
class RouterRecord(_OldRouterClass):
    class Test:
        def __init__(self, ports = set(), circ_id = None):
            self.circ_id = circ_id
            self.start_time = 0
            self.end_time = 0
            self.test_ports = set(ports)
            self.working_ports = set()
            self.failed_ports  = set()
            self.narrow_ports  = set()
            self.circ_failed = False

        def passed(self, port):
            self.working_ports.add(port)

        def failed(self, port):
            self.failed_ports.add(port)

        def narrow(self, port):
            self.narrow_ports.add(port)
            
        def start(self):
            self.start_time = time.time()
            return self

        def end(self):
            self.end_time = time.time()
            return self

        def is_complete(self):
            return self.test_ports <= \
                (self.working_ports | self.failed_ports | self.narrow_ports)

    def __init__(self, *args, **kwargs):
        _OldRouterClass.__init__(self, *args, **kwargs)
        self.actual_ip     = None
        self.last_test = self.Test()
        self.current_test = None
        self.circ_id = None  # Router's current circuit ID, if any.
        self.guard   = None  # Router's entry guard.  Only set with self.circuit.
        self.unreachable = False # Router is not reachable by active testing module.
        self.stale   = False # Router has fallen out of the consensus.
        self.stale_time = 0  # Time when router fell out of the consensus.

        self.circuit_failures  = 0
        self.circuit_successes = 0
        self.guard_failures  = 0
        self.guard_successes = 0
        self.retry = False

    def __hash__(self):
        return self.idhex.__hash__()

    def __eq__(self, other):
        return self.idhex == other.idhex

    def __ne__(self, other):
        return self.idhex != other.idhex

    def is_exit_policy_reject(self):
        """ Returns True if this router's exit policy is one line:
        reject *:*. """
        ep = self.exitpolicy[0]
        return len(self.exitpolicy) == 1 and \
            (ep.ip, ep.netmask, ep.port_low, ep.port_high) == (0, 0, 0, 0xffff)

    def is_narrow_exit(self, ip, port):
        """ Returns True if this router accepts exit traffic to port
        on some IP addresses but rejects traffic to ip. This can be
        used to detect exit enclaves. """
        can_accept = False
        for line in self.exitpolicy:
            if not line.match and line.ip == 0 and \
                    (port >= line.port_low and port <= line.port_high):
                can_accept = False
                break

            if line.match and (port >= line.port_low and port <= line.port_high):
                can_accept = True
                break

        return can_accept and not self.will_exit_to(ip, port)

    def should_export(self):
        """ Returns True if we have found working exit ports, or if we
        have not found working test ports, if this router has a non-reject-all
        exit policy. """
        return not self.unreachable and \
            (len(self.last_test.working_ports) != 0 or not self.is_exit_policy_reject())
    
    def is_ready(self):
        """ Returns True if this router ready for a new test; that is,
        it is not currently being tested and it is testable. """
        return (not self.current_test and self.last_test.test_ports)

    def new_test(self, test_ports, circ_id):
        """ Create a new RouterRecord.Test as current_test. """
        self.current_test = self.Test(test_ports, circ_id = circ_id)

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
#        self.test_ports = self.exit_ports(config.test_host, config.test_port_list)

    def exit_ports(self, ip, port_set):
        """ Return the set of ports that will exit from this router to ip
            based on the cached ExitPolicy. """
        return set(port_set)
        #return set(filter(lambda p: self.will_exit_to(ip, p), port_set))

    def _ep_line_compact(self, line):
        """ Return the most compact string representation possible for a
            given TorCtl.ExitPolicyLine. TorCtl.ExitPolicyLine.__str__
            exports a very verbose representation that greatly increases
            TorBEL's output size. This gives around 30% savings, depending
            on how complicated the average exit policy line is. """
        # 0.0.0.0/0.0.0.0 => *
        if line.ip == 0 and line.netmask == 0:
            ip = "*"
        else:
            def netmask_to_prefixlen(netmask, length):
                if netmask == 0:
                    return length
                for i in range(length):
                    if (netmask >> i) & 1:
                        return i

            ip  = socket.inet_ntoa(struct.pack(">I", line.ip))
            # Always convert netmask to a prefix length.
            if line.netmask != 0xffffffff:
                ip += "/" + str(netmask_to_prefixlen(line.netmask, 32))

        # Convert 0-65535 to *
        if line.port_low == 0 and line.port_high == 0xffff:
            port = "*"
        # Use 8 instead of 8-8
        elif line.port_low == line.port_high:
            port = str(line.port_low)
        else:
            port = "%d-%d" % (line.port_low, line.port_high)
                
        if line.match:
            return "accept " + ip + ":" + port
        else:
            return "reject " + ip + ":" + port

    def exit_policy_list(self):
        return map(lambda e: self._ep_line_compact(e), self.exitpolicy)

    def exit_policy_string(self):
        """ Collapse the router's ExitPolicy into one line, with each rule
            delimited by a semicolon (';'). """
        return ";".join(self.exit_policy_list())

    def dump(self, out):
        """ Serialize this record as a dictionary. """
        return { "ExitAddress": self.actual_ip if self.actual_ip else self.ip,
                 "RouterID":    self.idhex,
                 "Nickname":    self.nickname,
                 "InConsensus": not self.stale,
                 "LastTestedTimestamp": int(self.last_test.end_time),
                 "ExitPolicy":   self.exit_policy_list(),
                 "WorkingPorts": list(self.last_test.working_ports),
                 "FailedPorts":  list(self.last_test.failed_ports),
                 "NarrowPorts":  list(self.last_test.narrow_ports) }

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
                      self.exit_policy_string(),    # ExitPolicy
                      list(self.last_test.working_ports), # WorkingPorts
                      list(self.last_test.failed_ports),  # FailedPorts
                      list(self.last_test.narrow_ports)]) # NarrowPorts

    def __str__(self):
        return "%s (%s)" % (self.idhex, self.nickname)
# BOOM
TorCtl.Router = RouterRecord
