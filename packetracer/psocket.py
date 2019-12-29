"""
Simple socket wrapper for reading/writing on layer 2.
For all other use cases standard python sockets
should be used.
"""
import logging
import socket
import ssl

from packetracer import packetracer
from packetracer.layer12 import ethernet

logger = logging.getLogger("packetracer")


class SocketHndl(object):
    """
    Simple socket handler for layer 2 reading/writing.
    """
    ETH_P_ALL = 0x0003
    ETH_P_IPV4 = 0x0800

    def __init__(self, iface_name="lo",
                 timeout=3,
                 buffersize_recv=None,
                 buffersize_send=None, **params):
        """
        iface_name -- Bind to the given interface
        timeout -- read timeout in seconds
        buffersize_recv, buffersize_send -- amount of bytes used for receiving and sending
        """

        self.iface_name = iface_name
        self._socket = None
        # man 7 raw -> Receiving of all IP protocols via IPPROTO_RAW
        # is not possible using raw sockets.
        # socket(AF_INET, SOCK_RAW, IPPROTO_RAW)

        logger.info("creating socket, interface to bind on: %s", iface_name)
        try:
            self._socket = socket.socket(socket.AF_PACKET,
                                         socket.SOCK_RAW,
                                         socket.htons(SocketHndl.ETH_P_ALL))
        except OSError as err:
            logger.warning(err)
            logger.warning("Reducing receive scope to IPv4-only")
            self._socket = socket.socket(socket.AF_PACKET,
                                         socket.SOCK_RAW,
                                         socket.htons(SocketHndl.ETH_P_IPV4))

        if iface_name is not None:
            self._socket.bind((iface_name, SocketHndl.ETH_P_ALL))

        self._socket.settimeout(timeout)

        if buffersize_recv is not None:
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffersize_recv)
        if buffersize_send is not None:
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffersize_send)

    def send(self, bts):
        """
        Send the given bytes to network.

        bts -- the bytes to be sent
        """
        self._socket.send(bts)

    def recv(self, size=65536):
        """
        return -- bytes received from network
        """
        return self._socket.recv(size)

    def __enter__(self):
        return self

    def __exit__(self, objtype, value, traceback):
        self.close()

    def __iter__(self):
        """
        Call __next__() until StopIteration
        """
        try:
            while True:
                yield self.__next__()
        except StopIteration:
            return

    def __next__(self):
        try:
            return self.recv()
        except socket.timeout:
            raise StopIteration

    def recvp(self, filter_match_recv=lambda _: True, lowest_layer=ethernet.Ethernet, max_amount=1):
        """
        Receive packets from network. This does the same as calling recv() but using a receive
        filter and received bytes will be converted to packets using class given by lowest_layer.
        Raises socket.timeout on timeout

        filter_match_recv -- filter as callback function to match packets to be retrieved.
            Callback-structure: fct(packet), Return True to accept a specific packet.
            Raise StopIteration to stop receiving packets, max_amount will match after all.
        lowest_layer -- packet class to be used to create new packets
        max_amount -- maximum amount of packets to be fetched
        return -- packets received from network as list
        """
        received = []
        # logger.debug("listening for packets")

        while len(received) < max_amount:
            bts = self.recv()
            packet_recv = lowest_layer(bts)
            # logger.debug("got packet: %s" % packet_recv)
            try:
                if filter_match_recv(packet_recv):
                    received.append(packet_recv)
            except StopIteration:
                break
            except:
                # any other exception: ignore
                pass

        return received

    def recvp_iter(self, filter_match_recv=lambda _: True, lowest_layer=ethernet.Ethernet):
        """
        Same as recvp but using iterator returning one packet per cycle.
        """
        while True:
            try:
                bts = self.recv()
            except socket.timeout:
                return

            packet_recv = lowest_layer(bts)
            # logger.debug("got packet: %s" % packet_recv)
            try:
                if filter_match_recv(packet_recv):
                    yield packet_recv
            except StopIteration:
                return
            except:
                continue

    def sr(self, packet_send, max_packets_recv=1, pfilter=lambda _: True, lowest_layer=ethernet.Ethernet):
        """
        Send a packet and receive answer packets. This will use information retrieved
        from direction() to retrieve answer packets. This is not 100% reliable as
        it primarily depends on source/destination data of layers like Ethernet, IP etc.
        Raises socket.timeout on timeout.

        packet_send -- packetracer packet to be sent
        max_packets_recv -- max packets to be received
        pfilter -- filter as lambda function to match packets to be retrieved,
            return True to accept a specific packet.
        lowest_layer -- packet class to be used to create new packets

        return -- packets receives
        """

        received = []
        packet_send_clz = packet_send.__class__

        self.send(packet_send.bin())

        while len(received) < max_packets_recv:
            bts = self.recv()
            packet_recv = lowest_layer(bts)
            # logger.debug("got packet: %s" % packet_recv)
            if not pfilter(packet_recv):
                # filter didn't match
                continue

            # start to compare on corresponding receive-layer
            if packet_send.is_direction(packet_recv[packet_send_clz], packetracer.Packet.DIR_REV):
                # logger.debug("direction matched: %s" % packet_recv)
                received.append(packet_recv)

        return received

    def close(self):
        try:
            self._socket.close()
        except:
            pass


def get_ssl_clientsocket(hostname, port, timeout=5, **sslparams):
    """
    return -- SSL wrapped TCP socket, not complaining about any server certificates
    """
    context = ssl.create_default_context()
    socket_simple = socket.create_connection((hostname, port))
    socket_ssl = context.wrap_socket(socket_simple, server_hostname=hostname, **sslparams)
    socket_ssl.settimeout(timeout)
    return socket_ssl


def get_ssl_serversocket(file_certchain, file_privatekey, bindoptions, password_privkey=None):
    """
    Create a SSL based server socket. Useage:
    conn, addr = ssock.accept()
    data = conn.recv()
    conn.send(data)

    Certificate/private key can be create via:
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

    return -- SSL wrapped TCP server socket
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(file_certchain, file_privatekey, password=password_privkey)

    socket_simple = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    socket_simple.bind(bindoptions)
    socket_simple.listen(5)

    return context.wrap_socket(socket_simple, server_side=True)


# TCP/UDP server and client example code
# Server
"""
# ncat 127.0.0.1 80
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # IPv6: AF_INET6
serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serversocket.bind(("127.0.0.1", 80))
serversocket.listen(5)
(ssock, address) = serversocket.accept()
data = ssock.recv(1024)
print(data)
ssock.send(data)
"""

"""
# ncat 127.0.0.1 80 -u
serversocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # IPv6: AF_INET6
serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serversocket.bind(("127.0.0.1", 80))
data, address = serversocket.recvfrom(1024)
print(data)
serversocket.sendto(data, address)
"""

# Client
"""
# ncat -l 80
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # IPv6: AF_INET6
s.connect(("127.0.0.1", 80))
data = s.recv(1024)
print(data)
s.send(data)
"""

"""
# ncat -l 80 -u
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # IPv6: AF_INET6
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#s.bind(("127.0.0.1", 1234))
s.sendto(b"testtest", ("127.0.0.1", 80))
data, address = s.recvfrom(1024)
print(data)
"""
