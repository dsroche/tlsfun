#!/usr/bin/env python3

"""Tests the TLS client and server simultaneously over port 12345."""

import socket
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import logging

from tls_client import Client, ClientSecrets
from tls_server import Server
from tls_crypto import gen_cert
from tls_keycalc import ServerTicketer

logger = logging.getLogger('test_client_server')


class ServerTest:
    def __init__(self, hostname):
        logger.info(f'generating new self-signed cert for {hostname}')
        self._cert_secrets = gen_cert(hostname)
        self._ticketer = ServerTicketer()

    def go(self, ssock, in_msgs, out_msgs, rseed=None):
        server = Server(self._cert_secrets, self._ticketer, rseed)
        logger.info(f'server trying to connect and send {len(out_msgs)} messages')
        sock, addr = ssock.accept()
        logger.info(f'got a connection from client on {addr}')
        server.connect_socket(sock)
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
            assert im == expected, f'test case mismatch: server expected {expected}'
            om = next(outit)
            logger.info(f'server sending reply {om}')
            server.send(om)
        logger.info('TEST SUCCESS from server side')


class ClientTest:
    def __init__(self, hostname, port):
        self._hostname = hostname
        self._port = port

    def go(self, in_msgs, out_msgs, **ch_args):
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
                assert im == expected, f'test case mismatch: client expected {expected}'
        logger.info(f'TEST SUCCESS from client side, returning {len(client.tickets)} tickets')
        return client.tickets


class _CSTester:
    def __init__(self, hostname, port, ssock, executor):
        self._svt = ServerTest(hostname)
        self._clt = ClientTest(hostname, port)
        self._ssock = ssock
        self._executor = executor

    def __call__(self, requests, replies, rseed=None, **ch_args):
        logger.info('starting server for test run')
        sgo = self._executor.submit(self._svt.go, self._ssock, requests, replies, rseed)
        logger.info('starting client for test run')
        cgo = self._executor.submit(self._clt.go, replies, requests, rseed=rseed, **ch_args)
        sgo.result()
        logger.info('server finished test run')
        tiks = cgo.result()
        logger.info('client finished test run')
        return tiks


@contextmanager
def cs_test_runner(hostname, port):
    with socket.create_server((hostname, port)) as ssock:
        with ThreadPoolExecutor(max_workers=2) as executor:
            yield _CSTester(hostname, port, ssock, executor)


def do_tests(hostname='localhost', port=12345):
    with cs_test_runner(hostname, port) as trun:
        logger.info('starting simple ping/pong test')
        trun([b'ping'], [b'pong'])
        logger.info('TEST SUCCESS for ping/pong')

        logger.info('starting 2-round test with ticket')
        tiks = trun([b'one', b'two'], [b'three', b'four'])
        assert len(tiks) >= 1, 'did not receive any tickets'
        logger.info('TEST SUCCESS for 2-round getting tickets')

        logger.info('starting ticket redemption test')
        trun([b'a', b'b', b'c'], [b'd', b'e', b'f'], ticket=tiks[0])
        logger.info('TEST SUCCESS for 3-round using ticket')

    logger.info('ALL THREE TESTS PASSED')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    do_tests()
