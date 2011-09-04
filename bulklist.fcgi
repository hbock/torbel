#!/usr/bin/python
import sys, os

sys.path.append('/home/torbel')
sys.path.append('/home/torbel/torflow')
sys.path.append('/home/torbel/torbel')

import socket

from calendar import timegm

import torbel.query as query
from cgi import escape
from urlparse import parse_qs
from logger import *
from flup.server.fcgi import WSGIServer

import time
from threading import Timer

import math

from ipaddr import IPAddress

elist = None

log = get_logger("BulkExitList")

def update_elist():
    global elist
    elist = query.ExitList(filename = "/home/torbel/export/torbel_export.csv",
                           status_filename = "/home/torbel/export/torbel_export.status")
    nextUpdate = math.ceil(timegm(elist.next_update.timetuple()) - time.time())
    if nextUpdate > 0:
        log.debug("Scheduling update in %d seconds.", nextUpdate)
        Timer(nextUpdate, update_elist, ()).start()
    else:
        log.notice("Export file is not up-to-date. Trying again in 10 minutes.")
        Timer(10*60, update_elist, ()).start()

update_elist()

def app(environ, start_response):
    q = parse_qs(environ['QUERY_STRING'])


    ip = escape(q.get('ip', [''])[0])
    port = escape(q.get('port', [''])[0])

    if ip != "":
        try:
            ip = query.ip_from_string(ip) 
        except socket.error:
            ip = 0

    if ip != 0:
        try:
            port = int(port)
            if port > 65535 or port < 1:
                port = 80
        except ValueError:
            port = 80
        exits = elist.will_exit_to(ip, port)

        start_response('200 OK', [('Content-Type', 'text/plain')])

        yield "# This is a list of all Tor exit nodes that can contact %s " % IPAddress(ip)
        yield "on Port %d #\n" % port
        yield "# This file was generated on %s UTC #\n" % time.asctime(time.gmtime())
        exits.sort()
        for i in exits:
            yield '%s\n' % IPAddress(i)
    else:
        start_response('200 OK', [('Content-Type', 'text/plain')])
        yield 'bai'


if __name__ == "__main__":
    WSGIServer(app).run()

