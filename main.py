import argparse
import socket
from threading import Thread

import socks5


def parse_args():
    parser = argparse.ArgumentParser(
        description='ESP32-S3 Reverse Tunnel Relay Server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes (can be combined except -t with -s):
  SOCKS5 proxy    -s
  HTTP proxy      -H PORT
  TCP forward     -t HOST:PORT  (listens on -l PORT)

Examples:
  %(prog)s -s -H 8080                     SOCKS5 on 6669 + HTTP proxy on 8080
  %(prog)s -H 8080                         HTTP proxy only
  %(prog)s -t 192.168.1.10:22 -l 2222     Forward local :2222 -> home SSH
        """,
    )
    parser.add_argument(
        '-r', '--remote', default='6668', metavar='PORT',
        help='port the ESP32 connects to (default: 6668)',
    )
    parser.add_argument(
        '-l', '--local', default='6669', metavar='PORT',
        help='SOCKS5 or TCP-forward listening port (default: 6669)',
    )
    parser.add_argument(
        '-s', '--socks5', action='store_true',
        help='enable SOCKS5 proxy on -l port',
    )
    parser.add_argument(
        '-H', '--http', metavar='PORT',
        help='enable HTTP proxy on this port',
    )
    parser.add_argument(
        '-t', '--target', metavar='HOST:PORT',
        help='static TCP forward — all connections to -l port are tunnelled to HOST:PORT',
    )
    return parser.parse_args()


class EspListener(Thread):
    """Accepts inbound ESP32 connections and feeds them into the tunnel queue."""
    daemon = True

    def __init__(self, port, tunnel_queue):
        Thread.__init__(self)
        self._queue = tunnel_queue
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(('0.0.0.0', port))
        self._server.listen(200)
        print('ESP listener    0.0.0.0:%d' % port)

    def run(self):
        while True:
            conn, addr = self._server.accept()
            print('ESP connected from %s:%d' % addr)
            self._queue.put(conn)


def main(args):
    remote_port = int(args.remote)
    local_port  = int(args.local)

    tq = socks5.TunnelQueue()

    EspListener(remote_port, tq).start()

    if args.target:
        # Static TCP forward mode
        host, port_str = args.target.rsplit(':', 1)
        srv = socks5.TcpForwardServer(local_port, host, int(port_str), tq)
        if args.http:
            socks5.HttpProxyServer(int(args.http), tq).start_background()
        srv.serve_forever()
    else:
        # Proxy mode: SOCKS5 always starts, HTTP proxy is optional.
        socks5.Socks5Server.allow_reuse_address = True
        srv = socks5.Socks5Server(local_port, tunnel_queue=tq)
        print('SOCKS5 proxy    0.0.0.0:%d' % local_port)
        if args.http:
            socks5.HttpProxyServer(int(args.http), tq).start_background()
        srv.serve_forever()


if __name__ == '__main__':
    main(parse_args())
