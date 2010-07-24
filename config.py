from logger import *
import time

t = int(time.time())
## Connection settings for Tor.
tor_port = 9050
tor_host = "localhost"

## Connection settings for the Tor control port.
control_port = 9051
control_password = "torbeltest"

## TorBEL test settings.
# When should we stop exporting routers that have fallen out of the
# global consensus?  Timeout value in seconds.
stale_router_timeout = 60 * 60 * 4

# Complete list of ports to test exiting from.
#test_port_list = [53, 143, 443, 6667, 8080, 8443, 9000, 3000, 4050]
test_port_list = [21, 23, 25, 43, 53, 80, 88, 110, 115, 123, 143, 443,
                  706, 993, 995, 5190, 6667, 8080, 8443]

# What IP should TorBEL be binding on?
# If test_bind_ip is None or empty, we will use
# Tor's guess at our external IP address.
test_bind_ip = ""
test_host = ""

max_built_circuits = 200

csv_export_file = "bel_export.csv"
csv_gzip = False

# Should TorBEL run as a daemon?
daemonize = False
user  = "hbock"
group = "hbock"

log_level = DEBUG
log_syslog = daemonize
log_file   = "torbel-%d.log" % t
log_stdout = not daemonize
torctl_log_level = INFO
torctl_debug = True
torctl_debug_file = "torbel-%d-Control.log" % t
