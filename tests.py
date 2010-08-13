#!/usr/bin/env python
# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.

## TorBEL unit test suite.
from __future__ import with_statement

import sys, os
import socket, signal, errno
import time

from twisted.internet import error
from TorCtl import TorCtl
from torbel import logger, controller
from torbel.controller import config
from torbel.utils import config_check, ConfigurationError

log = logger.create_logger("torbelTests", config.log_level)

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

        while True:
            try:
                time.sleep(6)
            except KeyboardInterrupt:
                break

            # TODO: Do something.

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
