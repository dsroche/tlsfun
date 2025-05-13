# tlsfun
A partial implementation of TLS 1.3 in pure python for experimentation and fun times

## Disclaimer

**This library is bad, insecure code written by an academic and
should not be used by anyone.**

## Dependencies

*   Python 3.11 or later
*   [pyca cryptography (pip)](https://pypi.org/project/cryptography/)

## Quickstart

1.  Create virtual env in subdirectory `venv`

        python3 -m venv --prompt tlsfun venv

2.  Activate virtual env in the current shell

        . venv/bin/activate

3.  Install dependencies in the venv

        python3 -m pip install cryptography

4.  Test with a static example (not over the network)

        git clone https://github.com/syncsynchalt/illustrated-tls13
        ./test_example.py

## Simple HTTPS client and server

The `https_client.py` program can be used to make GET request, optionally using
reconnect tickets.

For example:

    ./https_client.py github.com

Unsurprisingly, the `https_server.py` runs a simple server over TLS
that responds to GET requests with a transcript of the TLS connection.
Try running it with

    ./https_server.py -p 8000

and then visiting <https://localhost:8000/> in your browser.
(Note, you will probably need to click through a warning because
the certificate is self-signed.)

Use `--help` for more usage details of both programs.


## Python module layout

*   `test_example.py`: Check this implementation against the example in
    Michael Driscoll's [Illustrated TLS 1.3](https://tls13.xargs.org/)

*   `https_client.py`: Runnable python module to create a client connection to
    an HTTPS server running TLS 1.3, optionally saving/using tickets.

*   `https_server.py`: Runnable python module to spawn a multi-threaded
    TLS 1.3 server which issues/uses tickets and responds to simple HTTP
    GET requests.

*   `tls_client.py`: Contains `Client` class for creating TLS 1.3 client-side
    connections.

*   `tls_server.py`: Contains `Server` class as well as a useful
    `start_server` function.

*   `tls13_spec.py`: Network message structures and constants translated
    from RFC 8446 into Python

*   `tls_keycalc.py`: Key schedule and ticket calculation code
    (without cryptographic details)

*   `tls_records.py`: Messages in TLS are structured into "records".
    This module deals with decoding/encoding and buffering these records
    in a TLS 1.3. connection.

*   `tls_crypto.py`: Implementations of cipher suites, hash algorithms,
    signature suites, etc. Mostly uses
    [pyca/cryptography](https://cryptography.io/)

*   `tls_common.y`: Exceptions and logging stuff

*   `spec.py`: Code to handle structured encoding/decoding of network
    messages (not TLS specific)

*   `util.py`: A few helper functions, not TLS specific

## Credit

This was written by Dan Roche (<https://roche.work>) while on sabbatical
at Boston University in 2024-2025.

The license is 0BSD: do whatever you want, just don't sue me.
