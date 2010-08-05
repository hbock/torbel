# Copyright 2010 Harry Bock <hbock@ele.uri.edu>
# See LICENSE for licensing information.
from __future__ import with_statement

import socket, struct
from twisted.internet import defer, error
from twisted.internet.protocol import Protocol, Factory, ClientFactory
from torbel.logger import *

log = get_logger("torbel")

class TestServer(Protocol):
    def connectionMade(self):
        self.host = self.transport.getHost()
        self.peer = self.transport.getPeer()
        self.data = ""

        log.verbose2("Connection from %s:%d", self.peer.host, self.host.port)

    def dataReceived(self, data):
        self.data += data
        if len(self.data) >= 40:
            self.factory.handleTestData(self.transport, self.data)
            self.transport.loseConnection()

    def connectionLost(self, reason):
        # Ignore clean closes.
        if not reason.check(error.ConnectionDone):
            # Ignore errors during shutdown.
            if reason.check(error.ConnectionLost) and self.factory.isTerminated():
                return
            log.verbose2("Connection from %s:%d lost: reason %s.",
                         self.peer.host, self.host.port, reason)
        
class TestServerFactory(Factory):
    protocol = TestServer

    def __init__(self, controller):
        self.controller = controller

    def isTerminated(self):
        return self.controller.terminated
    
    def handleTestData(self, transport, data):
        host = transport.getHost()
        peer = transport.getPeer()
        controller = self.controller

        with controller.consensus_cache_lock:
            if data in controller.router_cache:
                router = controller.router_cache[data]
            else:
                router = None

        # Make sure router is under test...
        if router and router.current_test:
            (ip,) = struct.unpack(">I", socket.inet_aton(peer.host))
            router.actual_ip = ip
            
            # TODO: Handle the case where the router exits on
            # multiple differing IP addresses.
            if router.actual_ip and router.actual_ip != ip:
                log.debug("%s: multiple IP addresses, %s and %s (%s advertised)!",
                             router.nickname, ip, router.actual_ip, router.ip)
            
            self.controller.passed(router, host.port)
        # Otherwise drop the connection.
        else:
            log.verbose2("Bad data from peer: %s", repr(data))
            transport.loseConnection()

    def clientConnectionLost(self, connector, reason):
        log.debug("Connection from %s lost, reason %s", connector, reason)
    
    def clientConnectionFailed(self, connector, reason):
        log.debug("Connection from %s failed, reason %s", connector, reason)

class TestClient(Protocol):
    """ Implementation of SOCKS4 and the testing "protocol". """
    SOCKS4_SENT, SOCKS4_CONNECTED, SOCKS4_FAILED = range(3)
    
    def connectionMade(self):
        peer_host, peer_port = self.factory.peer
        self.transport.write("\x04\x01" + struct.pack("!H", peer_port) +
                             socket.inet_aton(peer_host) + "\x00")
        self.state = self.SOCKS4_SENT
        self.data = ""

        # Call the deferred callback with our stream source port.
        self.factory.connectDeferred.callback(self.transport.getHost().port)

    def dataReceived(self, data):
        # We should not receive data unless we just sent the SOCKS4 initial
        # handshake. If we do, ask the factory to do something about it
        # and terminate the connection.
        if self.state != self.SOCKS4_SENT:
            (_, port) = self.factory.peer
            self.factory.unknownData(port, data)
            self.transport.loseConnection()
            return

        if self.state == self.SOCKS4_SENT:
            self.data += data
            if len(self.data) == 8:
                (status,) = struct.unpack('xBxxxxxx', self.data)
                # 0x5A == success; 0x5B-5D == failure/rejected
                if status == 0x5A:
                    log.verbose2("SOCKS4 connect successful")
                    self.state = self.SOCKS4_CONNECTED
                    self.transport.write(self.factory.testData())
                else:
                    log.verbose2("SOCKS4 connect failed")
                    self.state = self.SOCKS4_FAILED
                    self.transport.loseConnection()
            elif len(self.data) > 8:
                log.error("BUG? Too much data received while waiting for SOCKS reply.")

class TestClientFactory(ClientFactory):
    protocol = TestClient
    def __init__(self, peer, router, controller):
        self.controller = controller
        self.router = router
        self.peer = peer
        self.connectDeferred = defer.Deferred()

    def testData(self):
        return self.router.idhex

    def unknownData(self, port, data):
        """ Called if we receive unexpected data from an exit node. """
        log.info("unexpected data in stream from %s(%s): %s",
                 self.router.idhex, self.router.nickname, repr(data))

        # As of 7/24/10, I have only seen this happen when an exit node
        # is running exit traffic for a particular port through a POP3
        # proxy.  (-ERR AVG POP3 Proxy Server: Cannot connect to the mail server!)
        # I believe it is trying to connect to TorBEL as if it were a
        # mail client, thus we cannot handle this properly without
        # implementing a POP3 pseudo-client, which is for now outside
        # the scope of TorBEL.  
        # For now, we simply assume that the router will actually
        # connect to the mail server on its advertised IP address.
        # This is not the best solution but at worst it will produce a
        # rare false positive (as of this writing, I saw POP3 proxies
        # on 18 distinct routers out of 1700), which is better than a
        # false negative in this case.
        self.controller.passed(self.router, port)

    def clientConnectionLost(self, connector, reason):
        pass   

    def clientConnectionFailed(self, connector, reason):
        pass
