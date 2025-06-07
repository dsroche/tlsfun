#!/usr/bin/env python3

"""Perform simple HTTP GET requests over TLS."""

import socket
import argparse
import logging
import json

from tls_common import *
from tls_client import Client, build_client
from tls_keycalc import TicketInfo


def http_get_req(hostname: str, path: str = '/') -> bytes:
    return b''.join([
        b'GET ',
        path.encode('ascii'),
        b' HTTP/1.1\r\nHost: ',
        hostname.encode('ascii'),
        b'\r\n\r\n',
    ])


def tls_http(
    hostname: str,
    port    : int         = 443,
    path    : str         = '/',
    timeout : float|None  = None,
    client  : Client|None = None
) -> bytes:
    if client is None:
        logger.info(f'building client hello with sni {hostname}')
        client = build_client(sni=hostname)
    request = http_get_req(hostname, path)
    worked = False
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        client.connect_socket(sock)
        client.send(request)
        response = client.recv(2**16)
        sock.close()
    return bytes(response)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description = 'Connect to an HTTPS server using TLS 1.3 and make a GET request.',
    )
    parser.add_argument('hostname')
    parser.add_argument('-p', '--port', type=int, default=443)
    parser.add_argument('-g', '--get', default='/', metavar='PATH',
        help='The path to make a GET request on; default is the root webpage "/"')
    parser.add_argument('-t', '--timeout', type=int, default=None)
    parser.add_argument('-s', '--store-ticket', type=argparse.FileType('w'), metavar='FILENAME',
        help='If a PSK reconnect ticket is received, save it to the given filename.')
    parser.add_argument('-u', '--use-ticket', type=argparse.FileType('r'), metavar='FILENAME',
        help='Attempt to use the ticket int he given filename to connect in PSK mode.')
    parser.add_argument('-q', '--quiet', action='store_true')
    args = parser.parse_args()

    if not args.quiet:
        logging.basicConfig(level=logging.INFO)

    ticket: TicketInfo|None = None
    if args.use_ticket:
        ticket = TicketInfo.from_json(json.load(args.use_ticket))

    client = build_client(sni=args.hostname, ticket=ticket)

    resp = tls_http(args.hostname, args.port, args.get, args.timeout, client)

    if args.store_ticket:
        if client.tickets:
            json.dump(client.tickets[0].jsonify(), args.store_ticket)
            if not args.quiet:
                print(f'\ngot {len(client.tickets)} tickets and saved one')
        elif not args.quiet:
            print('\nWARNING: did not receive any reconnect ticket to save')

    if not args.quiet:
        print()
        print("First five lines of response:")
        for line in resp.decode().split('\n')[:5]:
            print('   ', line.rstrip()[:72])
