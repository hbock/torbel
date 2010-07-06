#!/usr/bin/python
import sys, os
import query
from cgi import escape
from logger import *
from flup.server.fcgi import WSGIServer

elist = query.ExitList(csv_file = "bel_export.csv")
port = 8000

log = get_logger("WSGITest")

def app(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])
    ipstr = environ["REMOTE_ADDR"]
    ip    = query.ip_from_string(environ["REMOTE_ADDR"])
    router = elist.is_tor_traffic(ip, port)

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
    

