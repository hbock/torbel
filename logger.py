# TorBEL logging helper module.
# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.
import logging
from TorCtl import TorUtil

# Import logging module default levels for torbel_config simplification.
from logging import DEBUG, INFO, WARN, WARNING, ERROR, CRITICAL
from logging.handlers import SysLogHandler

NOTICE = INFO + 5
# Set up extra verbosity levels.
VERBOSE1, VERBOSE2, VERBOSE3 = 3, 2, 1
logging.addLevelName(NOTICE,   "NOTICE")
logging.addLevelName(VERBOSE1, "DEBUGV")
logging.addLevelName(VERBOSE2, "DEBUGVV")
logging.addLevelName(VERBOSE3, "DEBUGVVV")

torutil_level_mapper = {
    VERBOSE3: "DEBUG",
    VERBOSE2: "DEBUG",
    VERBOSE1: "DEBUG",
    DEBUG:    "DEBUG",
    INFO:     "INFO",
    NOTICE:   "NOTICE",
    WARN:     "WARN",
    WARNING:  "WARN",
    ERROR:    "ERROR",
    CRITICAL: "ERROR"
}

# Basic output for all formats.  Useful alone when date/time is provided by handler
# (e.g., syslog)
basic_format = "%(name)-6s %(levelname)-8s %(message)s"
basic_formatter = logging.Formatter(basic_format)
# Basic output prefixed with the date and time.
dated_format = "[%(asctime)s] " + basic_format
dated_formatter = logging.Formatter(dated_format, "%b %d %H:%M:%S")

def create_logger(name, level, torctl_level = INFO,
                  syslog = False, stdout = True, file = None):
    """ Get the logger associated with 'name' and add relevant handlers to it
        based on syslog, stdout, and file. """
    log = logging.getLogger(name)
    if hasattr(log, "_tb_initialized"):
        return log

    if stdout:
        ch = logging.StreamHandler()
        ch.setFormatter(dated_formatter)
        log.addHandler(ch)
    if syslog:
        s = SysLogHandler(facility = SysLogHandler.LOG_DAEMON, address = "/dev/log")
        s.setFormatter(basic_formatter)
        log.addHandler(s)
    if file:
        f = logging.FileHandler(file)
        f.setFormatter(dated_formatter)
        log.addHandler(f)
        
    log.setLevel(level)
    # Set TorCtl log level (see TorCtl/TorUtil.py:def plog)
    # Not sure how to actually set up the TorCtl config file...
    TorUtil.loglevel = torutil_level_mapper[torctl_level]


    log._tb_initialized = True
    return log

def get_logger(name):
    """ Return the logger associated with name. """
    return logging.getLogger(name)

def stop_logging():
    logging.shutdown()
