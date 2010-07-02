# TorBEL logging helper module.
# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.
import logging
from TorCtl import TorUtil

# Import logging module default levels for torbel_config simplification.
from logging import DEBUG, INFO, WARN, WARNING, ERROR, CRITICAL
# Set up extra verbosity levels.
VERBOSE1, VERBOSE2, VERBOSE3 = 3, 2, 1
logging.addLevelName(VERBOSE1, "DEBUGV")
logging.addLevelName(VERBOSE2, "DEBUGVV")
logging.addLevelName(VERBOSE3, "DEBUGVVV")

# Set TorCtl log level (see TorCtl/TorUtil.py:def plog)
# Not sure how to actually set up the TorCtl config file...
TorUtil.loglevel = "INFO"
default_loglevel = DEBUG

def set_log_level(_level):
    default_loglevel = _level

def get_logger(name, level = default_loglevel):
    log = logging.getLogger(name)
    log.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter("[%(asctime)s] %(name)-15s %(levelname)-8s : %(message)s",
                                      "%b %d %H:%M:%S")) 
    log.addHandler(ch)

    return log
