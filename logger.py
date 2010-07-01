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

def set_log_level(_level):
    level = _level
    log.setLevel(level)
    ch.setLevel(level)

def get_logger(name, level = DEBUG):
    log = logging.getLogger(name)
    log.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter("%(name)s.%(levelname)s [%(asctime)s]: %(message)s",
                                      "%b %d %H:%M:%S")) 
    log.addHandler(ch)

    return log
