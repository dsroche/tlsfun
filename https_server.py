#!/usr/bin/env python3

"""TLS server responding to HTTP GET requests."""

import socket
import argparse

from tls_common import *
from tls_server import start_server, server_thread_info


class HttpHandler:
    """Simple handler for https connections."""
    def __call__(self, server):
        logger.info('waiting for HTTP request from client')
        request = server.recv(1 << 14)
        hs = server._handshake
        logbuf = server_thread_info.log_buffer
        logbuf.seek(0)
        logs = logbuf.read()
        response_contents = '\r\n'.join([
            f'tlsfun https server is working!',
            '',
            'server log messages:',
            '='*72,
            logs,
            '='*72,
            '',
            f'HTTP request is copied below.',
            '='*72,
            request.decode('utf8')
        ]).encode('utf8')
        response = '\r\n'.join([
            'HTTP/1.0 200 OK',
            'Content-type: text/plain',
            f'Content-Length: {len(response_contents)}',
            '\r\n',
        ]).encode('utf8') + response_contents
        server.send(response)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description = 'Start an HTTPS server using TLS 1.3 and respond to GET requests.',
    )
    parser.add_argument('-n', '--hostname', default='localhost',
        help='The hostname to listen on; default is localhost.')
    parser.add_argument('-p', '--port', type=int, default=8000,
        help='Port to listen for connections; default is 8000')
    parser.add_argument('-q', '--quiet', action='store_true')
    args = parser.parse_args()

    if not args.quiet:
        logging.basicConfig(level=logging.INFO)

    start_server(HttpHandler(), args.hostname, args.port)
