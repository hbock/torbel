import socket
import struct
import errno

class socks4socket(socket.socket):
    SOCKS4_CONNECTED, SOCKS4_FAILED, SOCKS4_INCOMPLETE = range(3)

    def __init__(self, proxy_host, proxy_port):
        socket.socket.__init__(self, socket.AF_INET, socket.SOCK_STREAM)
        self.peer_host = None
        self.peer_port = None
        self.proxy_port = proxy_port
        self.proxy_host = proxy_host
        self.resp = ""
        
    def getpeername(self):
        return (self.peer_host, self.peer_port)

    def getproxyname(self):
        return (self.proxy_host, self.proxy_port)
    
    def connect(self, peer):
        self.peer_host, self.peer_port = peer
        socket.socket.connect(self, (self.proxy_host, self.proxy_port))
        self.send("\x04\x01" + struct.pack("!H", self.peer_port) +
                  socket.inet_aton(self.peer_host) + "\x00")
        # Boom I'm CRAZY
        self.setblocking(0)

    def complete_handshake(self):
        try:
            self.resp += self.recv(8 - len(self.resp))
        except socket.error, e:
            # Interrupted by a signal, try again later.
            if e.errno == errno.EINTR:
                return self.SOCKS4_INCOMPLETE
        # If we receive less than the full SOCKS4 response, try again later.
        if len(self.resp) < 8:
            return self.SOCKS4_INCOMPLETE
        else:
            (status,) = struct.unpack('xBxxxxxx', self.resp)
            # 0x5A == success; 0x5B-5D == failure/rejected
            if status == 0x5a:        
                return self.SOCKS4_CONNECTED
            else:
                return self.SOCKS4_FAILED
