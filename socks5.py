# most part of this code comes from https://github.com/fengyouchao/pysocks/blob/master/socks5.py
# under the apache licence

import logging
import queue
import re
import select
import struct
import threading
import time
from socketserver import BaseServer, ThreadingTCPServer, StreamRequestHandler
from socket import socket, AF_INET, SOCK_STREAM, SHUT_RDWR


class TunnelQueue:
    """Thread-safe queue of available ESP32 tunnel sockets."""
    def __init__(self):
        self._q = queue.Queue()

    def put(self, sock):
        self._q.put(sock)

    def get(self, timeout=30):
        return self._q.get(timeout=timeout)

def byte_to_int(b):
    """
    Convert Unsigned byte to int
    :param b: byte value
    :return:  int value
    """
    return b & 0xFF


def port_from_byte(b1, b2):
    """

    :param b1: First byte of port
    :param b2: Second byte of port
    :return: Port in Int
    """
    return byte_to_int(b1) << 8 | byte_to_int(b2)


def host_from_ip(a, b, c, d):
    a = byte_to_int(a)
    b = byte_to_int(b)
    c = byte_to_int(c)
    d = byte_to_int(d)
    return "%d.%d.%d.%d" % (a, b, c, d)


def get_command_name(value):
    """
    Gets command name by value
    :param value:  value of Command
    :return: Command Name
    """
    if value == 1:
        return 'CONNECT'
    elif value == 2:
        return 'BIND'
    elif value == 3:
        return 'UDP_ASSOCIATE'
    else:
        return None


def build_command_response(reply):
    return b'\x05' + reply.get_byte_string() + b'\x00\x01\x00\x00\x00\x00\x00\x00'


def close_session(session):
    session.get_client_socket().close()
    logging.info("Session[%s] closed" % session.get_id())
    
class Session(object):
    index = 0

    def __init__(self, client_socket, proxy_socket):
        Session.index += 1
        self.__id = Session.index
        self.__client_socket = client_socket
        self.__proxy_socket = proxy_socket
        self._attr = {}

    def get_id(self):
        return self.__id

    def set_attr(self, key, value):
        self._attr[key] = value

    def get_client_socket(self):
        return self.__client_socket
      
    def get_proxy_socket(self):
        return self.__proxy_socket
      
class AddressType(object):
    IPV4 = 1
    DOMAIN_NAME = 3
    IPV6 = 4


class SocksCommand(object):
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3


class SocksMethod(object):
    NO_AUTHENTICATION_REQUIRED = 0
    GSS_API = 1
    USERNAME_PASSWORD = 2


class ServerReply(object):
    def __init__(self, value):
        self.__value = value

    def get_byte_string(self):
        return bytes([self.__value])

    def get_value(self):
        return self.__value


class ReplyType(object):
    SUCCEEDED = ServerReply(0)
    GENERAL_SOCKS_SERVER_FAILURE = ServerReply(1)
    CONNECTION_NOT_ALLOWED_BY_RULESET = ServerReply(2)
    NETWORK_UNREACHABLE = ServerReply(3)
    HOST_UNREACHABLE = ServerReply(4)
    CONNECTION_REFUSED = ServerReply(5)
    TTL_EXPIRED = ServerReply(6)
    COMMAND_NOT_SUPPORTED = ServerReply(7)
    ADDRESS_TYPE_NOT_SUPPORTED = ServerReply(8)
    
    
class SocketPipe(object):
    BUFFER_SIZE = 65536
    SELECT_TIMEOUT = 1.0

    def __init__(self, socket1, socket2):
        self._socket1 = socket1
        self._socket2 = socket2
        self.__running = False
        self.__stop_lock = threading.Lock()

    def __transfer(self, src, dst):
        while self.__running:
            try:
                ready, _, _ = select.select([src], [], [], self.SELECT_TIMEOUT)
                if not ready:
                    continue  # timeout — re-check __running
                data = src.recv(self.BUFFER_SIZE)
                if not data:
                    break
                dst.sendall(data)
            except OSError:
                break
        self.stop()

    def start(self):
        self.__running = True
        threading.Thread(target=self.__transfer, args=(self._socket1, self._socket2), daemon=True).start()
        threading.Thread(target=self.__transfer, args=(self._socket2, self._socket1), daemon=True).start()

    def stop(self):
        with self.__stop_lock:
            if not self.__running:
                return
            self.__running = False
        # shutdown() sends FIN/RST and immediately unblocks any recv() in other threads.
        # close() alone is not enough — on Linux it does not interrupt a blocking recv().
        for sock in (self._socket1, self._socket2):
            try:
                sock.shutdown(SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def is_running(self):
        return self.__running
      
    
class CommandExecutor(object):
    def __init__(self, remote_server_host, remote_server_port, session):
        self.__remote_server_host = remote_server_host
        self.__remote_server_port = remote_server_port
        self.__client = session.get_client_socket()
        self.__session = session

    def do_connect(self):
        """
        Do SOCKS CONNECT method
        :return: None
        """
        try:
            self.__session.get_proxy_socket().sendall(('%s:%s' % self.__get_address()).encode())
            self.__client.sendall(build_command_response(ReplyType.SUCCEEDED))
            socket_pipe = SocketPipe(self.__client, self.__session.get_proxy_socket())
            socket_pipe.start()
            while socket_pipe.is_running():
                time.sleep(0.05)
        except OSError:
            pass

    def do_bind(self):
        pass

    def do_udp_associate(self):
        pass

    def __get_address(self):
        return self.__remote_server_host, self.__remote_server_port
      
      
class User(object):
    def __init__(self, username, password):
        self.__username = username
        self.__password = password

    def get_username(self):
        return self.__username

    def get_password(self):
        return self.__password

    def __repr__(self):
        return '<user: username=%s, password=%s>' % (self.get_username(), self.__password)


class UserManager(object):
    def __init__(self):
        self.__users = {}

    def add_user(self, user):
        self.__users[user.get_username()] = user

    def remove_user(self, username):
        if username in self.__users:
            del self.__users[username]

    def check(self, username, password):
        if username in self.__users and self.__users[username].get_password() == password:
            return True
        else:
            return False

    def get_user(self, username):
        return self.__users[username]

    def get_users(self):
        return self.__users


class Socks5RequestHandler(StreamRequestHandler):
    def __init__(self, request, client_address, server):
        StreamRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        client = self.connection
        if self.server.allowed and self.client_address[0] not in self.server.allowed:
            client.close()
            return

        # SOCKS5 greeting
        client.recv(1)
        method_num, = struct.unpack('B', client.recv(1))
        methods = struct.unpack('B' * method_num, client.recv(method_num))
        auth = self.server.is_auth()
        if SocksMethod.NO_AUTHENTICATION_REQUIRED in methods and not auth:
            client.sendall(b"\x05\x00")
        elif SocksMethod.USERNAME_PASSWORD in methods and auth:
            client.sendall(b"\x05\x02")
            if not self.__do_username_password_auth():
                logging.info('Authentication failed from %s' % self.client_address[0])
                client.close()
                return
        else:
            client.sendall(b"\x05\xFF")
            return

        # SOCKS5 request
        version, command, reserved, address_type = struct.unpack('B' * 4, client.recv(4))
        host = None
        port = None
        if address_type == AddressType.IPV4:
            ip_a, ip_b, ip_c, ip_d, p1, p2 = struct.unpack('B' * 6, client.recv(6))
            host = host_from_ip(ip_a, ip_b, ip_c, ip_d)
            port = port_from_byte(p1, p2)
        elif address_type == AddressType.DOMAIN_NAME:
            host_length, = struct.unpack('B', client.recv(1))
            host = client.recv(host_length).decode()
            p1, p2 = struct.unpack('B' * 2, client.recv(2))
            port = port_from_byte(p1, p2)
        else:  # address type not support
            client.sendall(build_command_response(ReplyType.ADDRESS_TYPE_NOT_SUPPORTED))
            client.close()
            return

        if command == SocksCommand.CONNECT:
            try:
                proxy_socket = self.server.acquire_proxy_socket()
            except queue.Empty:
                client.sendall(build_command_response(ReplyType.GENERAL_SOCKS_SERVER_FAILURE))
                client.close()
                return
            session = Session(client, proxy_socket)
            logging.info("Session[%s] Request connect %s:%d" % (session.get_id(), host, port))
            CommandExecutor(host, port, session).do_connect()
            close_session(session)
        else:
            client.sendall(build_command_response(ReplyType.COMMAND_NOT_SUPPORTED))
            client.close()

    def __do_username_password_auth(self):
        client = self.connection
        client.recv(1)
        length, = struct.unpack('B', client.recv(1))
        username = client.recv(length).decode()
        length, = struct.unpack('B', client.recv(1))
        password = client.recv(length).decode()
        user_manager = self.server.get_user_manager()
        if user_manager.check(username, password):
            client.send(b"\x01\x00")
            return True
        else:
            client.send(b"\x01\x01")
            return False


class Socks5Server(ThreadingTCPServer):
    """
    SOCKS5 proxy server
    """

    def __init__(self, port, auth=False, user_manager=None, allowed=None, tunnel_queue=None):
        ThreadingTCPServer.__init__(self, ('', port), Socks5RequestHandler)
        self.__tunnel_queue = tunnel_queue if tunnel_queue is not None else TunnelQueue()
        self.__port = port
        self.__users = {}
        self.__auth = auth
        self.__user_manager = user_manager if user_manager is not None else UserManager()
        self.__sessions = {}
        self.allowed = allowed

    def serve_forever(self, poll_interval=0.5):
        logging.info("Create SOCKS5 server at port %d" % self.__port)
        ThreadingTCPServer.serve_forever(self, poll_interval)

    def finish_request(self, request, client_address):
        BaseServer.finish_request(self, request, client_address)

    def is_auth(self):
        return self.__auth

    def set_auth(self, auth):
        self.__auth = auth

    def get_all_managed_session(self):
        return self.__sessions

    def get_bind_port(self):
        return self.__port

    def acquire_proxy_socket(self, timeout=30):
        return self.__tunnel_queue.get(timeout=timeout)

    def set_proxy_socket(self, proxy_socket):
        self.__tunnel_queue.put(proxy_socket)

    def get_user_manager(self):
        return self.__user_manager

    def set_user_manager(self, user_manager):
        self.__user_manager = user_manager


# ---------------------------------------------------------------------------
# HTTP proxy (CONNECT for HTTPS, plain HTTP GET/POST/etc)
# Shares the same ESP socket queue as Socks5Server.
# ---------------------------------------------------------------------------

_HOP_BY_HOP = frozenset([
    b'proxy-connection', b'proxy-authorization', b'keep-alive',
    b'connection', b'transfer-encoding', b'te', b'trailers', b'upgrade',
])


def _recv_headers(sock):
    """Read bytes until \r\n\r\n without over-reading. Returns (header_block, leftover)."""
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return None, None
        buf += chunk
    idx = buf.index(b'\r\n\r\n')
    return buf[:idx], buf[idx + 4:]


class HttpProxyRequestHandler(StreamRequestHandler):
    def handle(self):
        client = self.connection
        try:
            header_block, leftover = _recv_headers(client)
            if header_block is None:
                return

            lines = header_block.split(b'\r\n')
            request_line = lines[0].decode('latin-1')
            parts = request_line.split(' ', 2)
            if len(parts) != 3:
                client.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                return
            method, target, http_version = parts

            if method.upper() == 'CONNECT':
                # HTTPS tunnel: target is host:port
                if ':' not in target:
                    client.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                    return
                host, port_str = target.rsplit(':', 1)
                port = int(port_str)

                try:
                    proxy_socket = self.server.acquire_proxy_socket()
                except queue.Empty:
                    client.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
                    return

                proxy_socket.sendall(('%s:%d' % (host, port)).encode())
                client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

                # leftover after headers is the first TLS ClientHello
                if leftover:
                    proxy_socket.sendall(leftover)

                pipe = SocketPipe(client, proxy_socket)
                pipe.start()
                while pipe.is_running():
                    time.sleep(0.05)

            else:
                # Plain HTTP: target is a full URL, e.g. http://example.com:80/path
                m = re.match(r'https?://([^/:]+)(?::(\d+))?(.*)', target)
                if not m:
                    client.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                    return
                host = m.group(1)
                port = int(m.group(2)) if m.group(2) else 80
                path = m.group(3) or '/'

                try:
                    proxy_socket = self.server.acquire_proxy_socket()
                except queue.Empty:
                    client.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
                    return

                proxy_socket.sendall(('%s:%d' % (host, port)).encode())

                # Rebuild request: rewrite URL to path, strip hop-by-hop headers,
                # downgrade to HTTP/1.0 to avoid keep-alive complications.
                rebuilt = ('%s %s HTTP/1.0\r\n' % (method, path)).encode()
                for line in lines[1:]:
                    if not line:
                        continue
                    name = line.split(b':', 1)[0].strip().lower()
                    if name not in _HOP_BY_HOP:
                        rebuilt += line + b'\r\n'
                rebuilt += b'Connection: close\r\n\r\n'

                proxy_socket.sendall(rebuilt)
                if leftover:
                    proxy_socket.sendall(leftover)

                pipe = SocketPipe(client, proxy_socket)
                pipe.start()
                while pipe.is_running():
                    time.sleep(0.05)

        except (OSError, ValueError):
            try:
                client.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            except OSError:
                pass


class HttpProxyServer(ThreadingTCPServer):
    """HTTP proxy server that tunnels through the shared ESP32 socket queue."""
    allow_reuse_address = True

    def __init__(self, port, tunnel_queue):
        ThreadingTCPServer.__init__(self, ('', port), HttpProxyRequestHandler)
        self.__port = port
        self.__tunnel_queue = tunnel_queue

    def acquire_proxy_socket(self, timeout=30):
        return self.__tunnel_queue.get(timeout=timeout)

    def start_background(self):
        t = threading.Thread(target=self.serve_forever, daemon=True)
        t.start()
        print('HTTP proxy listening on 0.0.0.0:%d' % self.__port)


class TcpForwardRequestHandler(StreamRequestHandler):
    def handle(self):
        client = self.connection
        try:
            proxy_socket = self.server.acquire_proxy_socket()
        except queue.Empty:
            client.close()
            return
        try:
            proxy_socket.sendall(('%s:%d' % (self.server.target_host, self.server.target_port)).encode())
            pipe = SocketPipe(client, proxy_socket)
            pipe.start()
            while pipe.is_running():
                time.sleep(0.05)
        except OSError:
            pass


class TcpForwardServer(ThreadingTCPServer):
    """Static TCP port forwarder through the ESP32 tunnel."""
    allow_reuse_address = True

    def __init__(self, port, target_host, target_port, tunnel_queue):
        ThreadingTCPServer.__init__(self, ('', port), TcpForwardRequestHandler)
        self.target_host = target_host
        self.target_port = target_port
        self.__tunnel_queue = tunnel_queue
        print('TCP forward  0.0.0.0:%d → %s:%d' % (port, target_host, target_port))

    def acquire_proxy_socket(self, timeout=30):
        return self.__tunnel_queue.get(timeout=timeout)