#!/usr/bin/python
import sys, os

sys.path.append('/home/torbel')
sys.path.append('/home/torbel/torflow')
sys.path.append('/home/torbel/torbel')

import torbel.query as query
from cgi import escape
from logger import *
from flup.server.fcgi import WSGIServer

import time
from threading import Timer

import math

elist = None

port = 80

log = get_logger("WSGITest")

def update_elist():
    global elist
    elist = query.ExitList(filename = "/home/torbel/export/torbel_export.csv",
                           status_filename = "/home/torbel/export/torbel_export.status")
    nextUpdate = math.ceil(time.mktime(elist.next_update.timetuple()) - time.time())
    if nextUpdate > 0:
        log.debug("Scheduling update in %d seconds.", nextUpdate)
        Timer(nextUpdate, update_elist, ()).start()
    else:
        log.notice("Export file is not up-to-date. Trying again in 10 minutes.")
        Timer(10*60, update_elist, ()).start()

update_elist()

def app(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])
    ipstr = environ["REMOTE_ADDR"]
    ip    = query.ip_from_string(ipstr)
    dest_ip = query.ip_from_string("78.47.18.106")
    router = elist.tor_exit_search(ip, dest_ip, port)

    yield '<h1>ARE YOU FROM TOR?</h1>'
    yield '<blink><strong>'
    if router:
        log.debug("Request from %s is from Tor: %s (%s).", ipstr, router.nickname,
                  router.idhex)
        yield "YES! Exit from %s." % router.nickname
    else:
        log.debug("Request from %s is probably not from Tor.", ipstr)
        yield "NOPE!"
    yield '</strong></blink>'

if __name__ == "__main__":
    log.debug("Loaded WSGI server (exit list has %d routers).", len(elist.cache_id))
    WSGIServer(app).run()
