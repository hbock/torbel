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
        yield '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" '
        yield '"http://www.w3.org/TR/REC-html40/loose.dtd">\n'
        yield '<html>\n'
        yield '<head>\n'
        yield '<meta http-equiv="content-type" content="text/html; '
        yield 'charset=utf-8">\n'
        yield '<title>Bulk Tor Exit Exporter</title>\n'
        yield '<link rel="shortcut icon" type="image/x-icon" '
        yield 'href="./favicon.ico">\n'
        yield '</head>\n'
        yield '<body>\n'
        yield '<center>\n'
        yield '\n'
        yield '<br>\n');

        yield '\n'

        yield 'Welcome to the Tor Bulk Exit List exporting tool.<br><br>\n'
        yield 'If you are a service provider and you wish to build a list '
        yield 'of possible Tor nodes that might contact one of your servers, '
        yield 'enter that single server address below. Giving you the whole '
        yield 'list means you can query the list privately, rather than '
        yield 'telling us your users\' IP addresses.\n'
        yield 'This list allows you to have a nearly real time authoritative '
        yield 'source for Tor exits that allow contacting your server on '
        yield 'port 80 or the given port.<br><br>\n'

        yield 'Please enter an IP address:<br>\n'
        yield '<form action="/cgi-bin/TorBulkExitList.py" name="ip">\n'
        yield '<input type="text" name="ip"><br>\n'
        yield '<input type="submit" value="Submit">'
        yield '</form>'

        yield '</center>\n'
        yield '</body>'
        yield '</html>'

if __name__ == "__main__":
    WSGIServer(app).run()

