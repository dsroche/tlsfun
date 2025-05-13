#!/usr/bin/env python3

"""Tests the TLS client and server simultaneously over port 12345."""

import socket
import logging

from tls_client import Client, ClientSecrets
from tls_server import Server
from tls_crypto import gen_cert
from tls_keycalc import ServerTicketer

logger = logging.getLogger(__name__)


class ServerTest:
    def __init__(self, hostname):
        logger.info(f'generating new self-signed cert for {hostname}')
        self._cert_secrets = gen_cert(hostname)
        self._ticketer = ServerTicketer()

    def go(sock, in_msgs, out_msgs, rseed=None):
        logger.info(f'server trying to connect and send {len(out_msgs)} messages')
        server = Server(self._cert_secrets, self._ticketer, rseed)
        logger.info(f'server handshake complete')
        inmit = iter(in_msgs)
        outit = iter(out_msgs)
        while True:
            try:
                expected = next(inmit)
            except StopIteration:
                break
            im = server.recv(2**14)
            logger.info(f'server received message {im}')
            if im != expected:
                logger.error(f'mismatch: server expected {expected}')
                return False
            om = next(outit)
            logger.info(f'server sending reply {om}')
            server.send(om)
        return True


class ClientTest:
    def __init__(self, hostname, port):
        self._hostname = hostname
        self._port = port

    def go(in_msgs, in_msgs, out_msgs, **ch_args):
        logger.info(f'client trying to connect and send {len(out_msgs)} messages')
        client = Client.build(sni=self._hostname, **ch_args)
        inmit = iter(in_msgs)
        outit = iter(out_msgs)
        with socket.create_connection((self._hostname, self._port), timeout=1) as sock:
            logger.info('TCP connection to server established')
            client.connect_socket(sock)
            logger.info('TLS handshake complete from client perspective')
            while True:
                try:
                    om = next(outit)
                except StopIteration:
                    break
                logger.info(f'client sending request {om}')
                client.send(om)
                expected = next(inmit)
                im = client.recv(2**14)
                logger.info(f'client received reply {im}')
                if im != expected:
                    logger.error(f'ERROR: but client expected {expected}')
                    return False, None
        return True, client.tickets


def run_test(svt, clt, requests, replies, **ch_args):
    #TODO HERE

