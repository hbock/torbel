import os, pwd, grp
from torbel import logger

class ConfigurationError(Exception):
    """ TorBEL configuration error exception. """
    def __init__(self, message):
        self.message = message

def check_type(config, var, t, func = None, errmsg = None):
    c = ConfigurationError
    v = getattr(config, var)
    if type(v) is not t:
        raise c("Expected type of %s to be %s, not %s." \
                        % (var, t, type(v)))
    if func and not func(v):
        raise c("%s: %s" % (var, errmsg))

## TODO: More sanity checks!
def config_check(config):
    """ Sanity check for TorBEL configuration. """
    c = ConfigurationError

    if not config.test_port_list:
        raise c("test_port_list must not be empty.")

    if not config.test_host:
        pass

    if config.control_port == config.tor_port:
        raise c("control_port and tor_port cannot be the same value.")

    # Ports must be positive integers not greater than 65,535.
    bad_ports = filter(lambda p: (type(p) is not int) or p < 0 or p > 0xffff,
                       config.test_port_list)
    if bad_ports:
        raise c("test_port_list: %s are not valid ports." % bad_ports)

    for var in ["tor_port", "control_port", "stale_router_timeout", "max_built_circuits"]:
        check_type(config, var, int, lambda x: x > 0, "Expected positive integer.")
    for var in ["export_gzip", "daemonize", "torctl_debug", "log_syslog", "log_stdout"]:
        check_type(config, var, bool)
    for var in ["export_file_prefix", "log_file", "torctl_debug_file",
                "control_password", "tor_host", "test_host", "test_bind_ip"]:
        check_type(config, var, str)
    for var in ["user", "group"]:
        v = getattr(config, var)
        if type(v) is not str and type(v) is not int:
            raise c("%s must be a valid username string or ID number." % var)

    check_type(config, "max_pending_factor", float)

    # Convert test_scheduler strings to class names.
    try:
        nameToClass = {
            "hammer": "HammerScheduler",
            "conservative": "ConservativeScheduler",
            }
        config.scheduler = nameToClass[config.test_scheduler.lower()]

    except KeyError:
        raise c("'%s' is not a valid scheduler type. Expected one of %s." \
                    % (config.test_scheduler, ", ".join(nameToClass.keys())))
    
    for var in ["log_level", "torctl_log_level"]:
        check_type(config, var, type(logger.DEBUG),
                   lambda l: l in (logger.VERBOSE2, logger.VERBOSE1, logger.DEBUG,
                                   logger.INFO, logger.NOTICE,
                                   logger.WARN, logger.ERROR, logger.CRITICAL),
                   "Invalid log level, expected one of VERBOSE2, VERBOSE1, DEBUG, INFO, NOTICE, WARN, ERROR, or CRITICAL.")
    
    if os.getuid() == 0:
        user, group = config.user, config.group
        if not user:
            raise c("Running as root: set user to drop privileges.")
        if not group:
            raise c("Running as root: set group to drop privileges.")

        try:
            if type(user) is int:
                u = pwd.getpwuid(user)
            else:
                u = pwd.getpwnam(user)
            config.uid = u.pw_uid
        except KeyError:
            raise c("User '%s' not found." % user)

        try:
            if type(group) is int:
                g = grp.getgrgid(group)
            else:
                g = grp.getgrnam(group)
            config.gid = g.gr_gid
        except KeyError:
            raise c("Group '%s' not found." % group)

