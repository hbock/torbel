#!/usr/bin/env python
# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.

## TorBEL unit test suite.
from __future__ import with_statement

import sys, os
import socket, struct, signal, errno
import time, random
import threading

from TorCtl import TorCtl

from twisted.internet import error, defer
from twisted.names import client

from torbel import logger, controller
from torbel.utils import config_check, ConfigurationError
from torbel.query import ExitList
from ipaddr import IPAddress

config = controller.config
log = logger.create_logger("torbelTests", config.log_level)
# HACK FIXME create reactor per-application
reactor = controller.reactor

dnsel_zone = "exitlist.torproject.org"
local_zone = "dnsel.torproject.org"

match = 0
mismatch = 0

def fight_thread(control):
    el = ExitList(filename = config.export_file_prefix + ".csv",
                  status_filename = config.export_file_prefix + ".status")
    log.info("Initialized exit list.")
    dnsel  = client.createResolver()
    torbel = client.createResolver(servers = [("localhost", 53)])
    log.info("Initialized resolvers.")

    def makeResultChecker(router):
        return lambda rlist: printResult(router, rlist)

    def printResult((router, dest, dest_port, qstr, dnsel_ok2), result_list):
        global match, mismatch
        dnsel_ok  = False
        torbel_ok = False
        torbel_el_ok = el.tor_exit_search(router.ip, dest, dest_port) is not None
        
        query = ""
        for (success, value) in result_list:
            if success:
                (a_names, auth, cnames) = value
                assert len(a_names) == 1
                for rec in a_names:
                    dnsel_ok  = dnsel_zone in str(rec.name)
                    torbel_ok = local_zone in str(rec.name)

        q = "%-15s -> %-15s:%-5d - " % (IPAddress(router.ip), IPAddress(dest), dest_port)
        
        if dnsel_ok2 and torbel_el_ok:
            log.info(q + "DNSEL and TorBEL agree on YES.")
            match += 1
        elif not (dnsel_ok2 or torbel_el_ok):
            log.info(q + "DNSEL and TorBEL agree on NO.")
            match += 1
        else:
            log.info(q + "mismatch: DNSEL = %s, TorBEL DNS = %s, TorBEL query = %s, q = %s",
                     "yes" if dnsel_ok2 else "no",
                     "yes" if torbel_ok else "no",
                     "yes" if torbel_el_ok else "no",
                     qstr)
            mismatch += 1

    def query(router, dest, dest_port):
        s = map(lambda o: str(ord(o)), struct.pack(">I", router.ip))
        d = map(lambda o: str(ord(o)), struct.pack(">I", dest))
        s.reverse()
        d.reverse()

        qstr = "%s.%d.%s.ip-port." % (".".join(s), dest_port,  ".".join(d))
        try:
            dnsel_ghbn = socket.gethostbyname(qstr + dnsel_zone) == "127.0.0.2"
        except socket.gaierror:
            dnsel_ghbn = False

        #dr = dnsel.lookupAddress(qstr + dnsel_zone)
        tr = torbel.lookupAddress(qstr + local_zone)
        dl = defer.DeferredList([tr], consumeErrors = True)
        dl.addCallback(makeResultChecker((router, dest, dest_port, qstr, dnsel_ghbn)))

    log.info("Starting tests.")
    # Test IPs selected at random from around the world.
    # Sources: http://www.countryipblocks.net
    dest_list = [
        "131.128.160.244", # US East (EDU)
        "72.14.204.99", # Google US
        "38.229.70.8",
        "206.65.190.138",
        "198.7.241.30",   # US East (EDU)
        "114.200.0.5",    # KR .0.0/13
        "115.31.96.25",   # KR .96.0/19
        "62.182.136.12",  # RU .136.0/21
        "62.182.192.16",  # RU .192.0/21 
        "62.182.200.100", # RU .200.0/21
        "82.151.128.124", # TK .128.0/19
        "93.190.216.55",  # TK .216.0/21
        "58.65.192.5",    # PK .192.0/19
        "192.160.188.54", # BR .0/24
        "192.146.157.20"  # BR .0/24
        ]
    dest_list = map(lambda i: int(IPAddress(i)), dest_list)
    # Test all the ports we configure, including random ones
    # distributed uniformly from the set of privileged ports
    # and from the set of unprivileged ports.
    # No duplicates.
    testports = set(config.test_port_list)
    lowports  = set(random.sample(xrange(1,1024), 5))
    highports = set(random.sample(xrange(1025, 65535), 5))
    port_list = list(testports | lowports | highports)

    # Test sources in the currently tracked consensus.
    for router in control.router_cache.values():
        dest = random.choice(dest_list)
        port = random.choice(port_list)
        query(router, dest, port)

    time.sleep(5)
    log.notice("%d match, %d mismatch (%.2f%% agreement).",
               match, mismatch, 100 * match / float(match + mismatch))
    log.info("Done testing.")
    reactor.stop()

# TorBEL vs. TorDNSEL: Fight to the Death
def torbel_fight():
    log.notice("TorBEL vs. TorDNSEL: Ultimate GSoC Fight Match 2010 starting.")

    # Configuration check.
    try:
        config_check(config)
    except ConfigurationError, e:
        log.error("Configuration error: %s", e.message)
        return 1
    except AttributeError, e:
        log.error("Configuration error: missing value: %s", e.args[0])
        return 1
        
    try:
        control = controller.Controller()
        # We don't want tests, only consensus tracking.
        control.start(tests = False)
        thr = threading.Thread(target = fight_thread, args = (control,))
        thr.start()
        reactor.run()

        thr.join()

    except socket.error, e:
        err, strerror = e.args
        if err == errno.ECONNREFUSED:
            log.error("Connection refused! Is Tor control port available?")
        else:
            log.error("Socket error, aborting (%s).", strerror)

        return 1

    except TorCtl.ErrorReply, e:
        log.error("Connection failed: %s", str(e))
        return 2

    except TorCtl.TorCtlClosed:
        pass

    
if __name__ == "__main__":
    def usage():
        print "Usage: %s [torhost [ctlport]]" % sys.argv[0]
        sys.exit(1)

    ret = torbel_fight()

    log.notice("TorBEL test suite exiting.")
    logger.stop_logging()
    sys.exit(ret)
