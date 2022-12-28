#!/usr/bin/env python3

import socket
import uuid
import random
import argparse
import time
import re
import platform
import sys
import ssl

from socket import SOL_SOCKET, SOL_IP, SO_REUSEADDR, SO_REUSEPORT, \
    SOCK_DGRAM, SOCK_STREAM, AF_INET, gethostbyname, gethostname

CA_PATH_DARWIN = "/etc/ssl/cert.pem"
CA_PATH_LINUX = "/etc/ssl/certs/ca-certificates.crt"


def create_sock(dst, port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
    ctx.set_ciphers('ALL@SECLEVEL=0')
    # TODO: write platform-independent method
    ctx.load_verify_locations(cafile=CA_PATH_DARWIN)
    _sock = socket.socket(AF_INET, SOCK_STREAM)
    server_host_name = "{}:{}".format(dst, port)
    _tls_sock = ctx.wrap_socket(_sock, server_hostname=server_host_name)
    return _tls_sock


def main():
    dst, port = sys.argv[1:3]
    port = int(port)
    to_domain = "{}:{}".format(dst, port)
    from_domain = gethostname()
    call_id = "{0}-{1}".format(gethostname(), str(uuid.uuid4()))
    s = create_sock(dst, port)

    # According to RFC3261, the branch ID MUST always begin with the characters
    # "z9hG4bK". It used as magic cookie. Beyond this requirement, the precise
    # format of the branch token is implementation-defined
    branch_id = "z9hG4bK{}".format(str(uuid.uuid4()))

    # these intervals are chosen to keep request size always constant
    cseq = random.randint(1000000000, 2147483647)
    tag_id = random.randint(1000000000, 2147483647)

    hdr = "\r\n".join([
        "OPTIONS sip:options@{} SIP/2.0".format(to_domain),
        "Via: SIP/2.0/TLS {};branch=;rport".format(from_domain, branch_id),
        "Max-Forwards: 70",
        "To: <sip:options@{}>".format(to_domain),
        "From: <sip:options@{}>;tag={}".format(from_domain, tag_id),
        "Call-ID: {}".format(call_id),
        "CSeq: {} OPTIONS".format(cseq),
        "Contact: <sip:options@{}>;transport=tls".format(from_domain),
        "Accept: application/sdp",
        "Content-Length: 0",
        "\r\n"  # for getting double \r\n at the end, as it need by RFC
    ])

    s.connect((dst, port))
    s.do_handshake()
    s.sendall(hdr.encode())

    # Receive data from server

    while True:
        data = ''
        data = s.recv(4096)
        if not data:
            print("Connection closed")
            break

        print(data)

    s.close()
    exit(0)

if __name__ == "__main__":
    main()