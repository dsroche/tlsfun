#!/usr/bin/env python3

"""Runs a local example test based on <https://tls13.xargs.org/>.

Be sure to download the example data files first by running

    git clone https://github.com/syncsynchalt/illustrated-tls13
"""

from pathlib import Path
from tls13_spec import ClientSecrets, ClientHelloHandshake
from tls_client import Client
from io import BytesIO
import logging

logger = logging.getLogger('test_example')

class Example:
    capdir = Path() / 'illustrated-tls13' / 'captures' / 'caps'

    def __init__(self) -> None:
        if not self.capdir.exists():
            raise FileNotFoundError('download example: git clone https://github.com/syncsynchalt/illustrated-tls13')
        self.client_hello = ClientHelloHandshake.unpack((self.capdir / 'clienthello').read_bytes())
        self.all_from_client = b''.join((self.capdir / fname).read_bytes() for fname in [
            'clienthello',
            'clientccs',
            'clientencfinished',
            'clientencdata',
        ])
        self.all_from_server = b''.join((self.capdir / fname).read_bytes() for fname in [
            'serverhello',
            'serverccs',
            'serverencextensions',
            'serverenccert',
            'serverenccertverify',
            'serverencfinished',
            'serverencticket1',
            'serverencticket2',
            'serverencdata',
        ])
        self.from_client = BytesIO()
        self.from_server = BytesIO(self.all_from_server)
        self.client_secret = bytes(32+i for i in range(32))
        self._started = False
        self._connected = False

    def go(self) -> None:
        logging.basicConfig(level=logging.INFO)
        self.start()
        self.connect()
        self.send()
        self.recv()
        self.check()

    def start(self) -> None:
        if not self._started:
            logger.info("starting client (preprocess client hello)")
            self.client = Client.create(
                ch = self.client_hello,
                secrets = ClientSecrets.create(
                    psk = b'',
                    kex_sks = [self.client_secret]
                ),
            )
            self._started = True

    def connect(self) -> None:
        self.start()
        if not self._connected:
            logger.info("connecting client (receive server replies)")
            self.client.connect_files(self.from_server, self.from_client)
            self._connected = True

    def send(self) -> None:
        if not self._connected:
            self.connect()
        logger.info("sending ping to server")
        sent = self.client.send(b'ping')
        assert sent == 4

    def recv(self) -> None:
        if not self._connected:
            self.connect()
        got = self.client.recv(4)
        logger.info(f"received {got.hex()} from server")
        assert got == b'pong'

    def check(self) -> None:
        assert self.from_client.getvalue() == self.all_from_client
        assert self.from_server.tell() == len(self.all_from_server)
        logger.info("example matches 100%")


if __name__ == '__main__':
    Example().go()
