#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals
"""
Small script which can perform simple SIP OPTIONS ping and read response.
Written in Python2.7-compatible style without any external dependencies
for CentOS 7 compatibility. Also, it was quite minified for comfortable
copypasting to REPL sacrificing some PEP-8 recommedations.
"""

import socket
import uuid
import random
import argparse
import time

VERSION = "0.0.1"
MAX_FORWARDS = 70  # times
PING_TIMEOUT = 10.0  # seconds
MAX_RECVBUF_SIZE = 1400  # bytes


def create_sip_request(
        dst_host,
        dst_port=5060,
        src_port=0,
        proto="udp"):
    """
    Generates serialized SIP header from source data
    :param src_port: (int) source port. Used in From: header
    :param dst_port: (int) destination port. Used in URI and To: header
    :param dst_host: (str) ip address or hostname of remote side.
    :param proto: (str) tcp or udp, otherwise ValueError will raise
    :returns: (string): SIP header in human-readable format. Don't forget to
                        encode it to bytes
    """
    my_hostname = socket.gethostname()
    call_id = "{0}-{1}".format(
        my_hostname,
        str(uuid.uuid4())
    )
    # According to RFC3261, the branch ID MUST always begin with the characters
    # "z9hG4bK". It used as magic cookie. Beyond this requirement, the precise
    # format of the branch token is implementation-defined
    branch_id = "z9hG4bK%s" % str(uuid.uuid4())
    cseq = random.randint(32767, 2147483647)
    tag_id = random.randint(32767, 2147483647)
    return "\r\n".join([
        "OPTIONS sip:options@%s:%d SIP/2.0" % (dst_host, dst_port),
        "Via: SIP/2.0/%s %s;branch=%s;rport" % (
            proto.upper(),
            my_hostname,
            branch_id
        ),
        "Max-Forwards: %s" % MAX_FORWARDS,
        "To: <sip:options@%s:%d>" % (dst_host, dst_port),
        "From: <sip:options@%s:%d>;tag=%d" % (my_hostname, src_port, tag_id),
        "Call-ID: %s" % call_id,
        "CSeq: %d OPTIONS" % cseq,
        "Contact: <sip:sip:options@%s>" % my_hostname,
        "Accept: application/sdp"
        "Content-Length: 0",
        "\r\n"  # for getting double \r\n at the end, as it need by RFC
    ])


def create_socket(proto="udp", src_host='', src_port=0, timeout=PING_TIMEOUT):
    """
    Function returns preconfigured socket for transport needs
    :param src_host: (str) source host or ip of interface (default "")
    :param src_port: (int) source port (default 0)
    :param proto: (str) transport protocol - "tcp" or "udp"
    :param timeout: (float) socket timeout
    :return: (socket.socket) socket prepared for transmission
    """
    sock_type = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
    sock = socket.socket(socket.AF_INET, sock_type)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    if src_host.startswith("127."):  # checking for loopback ip.
        sock.bind(('', src_port))
    else:
        sock.bind((src_host, src_port))
    sock.settimeout(timeout)
    return sock


def udp_send(dst_host, request, dst_port=5060, src_host='',
             src_port=0, timeout=PING_TIMEOUT):
    """
    Function performs single sending of SIP packet
    :param dst_host: (str) ip address or hostname
    :param request: (str) data to send
    :param dst_port: (int) destination port
    :param src_host: (str) source host or ip of interface
    :param src_port: (int) source port
    :param timeout: (float) socket timeout in seconds
    :returns: tuple(string, int, exc/None) - buffer, length and possible error
    """
    dst_ipaddr = socket.gethostbyname(dst_host)
    sock = create_socket(
        proto="udp",
        src_host=src_host,
        src_port=src_port,
        timeout=timeout
    )
    try:
        sock.sendto(request.encode(), (dst_ipaddr, dst_port))
        while True:
            data, addr = sock.recvfrom(MAX_RECVBUF_SIZE)
            remote_host, remote_port = addr
            if remote_host == dst_ipaddr and remote_port == dst_port:
                return data.decode(encoding="utf-8", errors="ignore"), \
                       len(data), \
                       None
    except (socket.timeout, socket.error) as e:
        return "", 0, e
    finally:
        sock.close()


def tcp_send(dst_host,
             request,
             dst_port=5060,
             src_host='',
             src_port=0,
             timeout=PING_TIMEOUT):
    """
        Function performs single sending of SIP packet
        :param dst_host: (str) ip address or hostname
        :param request: (str) data to send
        :param dst_port: (int) destination port
        :param src_host: (str) source host or ip of interface
        :param src_port: (int) source port
        :param timeout: (float) socket timeout in seconds
        :returns: tuple(string, int, exc/None) - buffer and length
        """
    sock = create_socket(
        proto="tcp",
        src_host=src_host,
        src_port=src_port,
        timeout=timeout
    )
    try:
        sock.connect((dst_host, dst_port))
        sock.sendall(request.encode())
        data = sock.recv(MAX_RECVBUF_SIZE)
        return data.decode(encoding="utf-8", errors="ignore"), len(data), None
    except (socket.timeout, socket.error) as e:
        return "", 0, e
    finally:
        sock.close()


def main():
    """
    void main( void )
    """
    ap = argparse.ArgumentParser()
    mandatory_args = ap.add_argument_group('mandatory arguments')
    mandatory_args.add_argument(
        "-d",
        dest='dst_sock',
        help="Destination host <ip/hostname>[:port]",
        type=str,
        action="store",
        required=True
    )
    ap.add_argument(
        "-p",
        dest="proto",
        help="Protocol ('udp' or 'tcp')",
        type=str,
        choices=('tcp', 'udp'),
        default='udp'
    )
    ap.add_argument(
        "-t",
        dest="sock_timeout",
        help="Socket timeout in seconds (float, default 10.0)",
        type=float,
        action="store",
        default=PING_TIMEOUT
    )
    ap.add_argument(
        "-s",
        dest="src_sock",
        help="Source iface [ip/hostname]:[port] (hostname part is optional, "
             "possible to type \":PORT\" form to just set srcport)",
        type=str,
        action="store"
    )
    ap.add_argument(
        "-v",
        dest="verbose_mode",
        help="Verbose mode (show sent and received content)",
        action="store_true"
    )
    ap.add_argument('-V', action='version', version=VERSION)

    args = ap.parse_args()
    if ":" in args.dst_sock:
        dst_host, dst_port = args.dst_sock.split(":")
        dst_port = int(dst_port)
        if not dst_host:
            print("ERROR: Specify destination host!")
            exit(1)
    else:
        dst_host = args.dst_sock
        dst_port = 5060
    if args.src_sock:
        if ":" in args.src_sock:
            src_host, src_port = args.src_sock.split(":")
            src_port = int(src_port)
            if not src_host:  # possible to set srcport only in ":33333" manner
                src_host = ''
        else:
            src_host = args.src_sock
            src_port = 0  # Source port 0 means dynamically allocatable one
    else:
        src_host = ''
        src_port = 0
    if args.proto == 'tcp':
        send_function = tcp_send
        request = create_sip_request(
            dst_host=dst_host,
            dst_port=dst_port,
            src_port=src_port,
            proto="tcp"
        )
    else:
        send_function = udp_send
        request = create_sip_request(
            dst_host=dst_host,
            dst_port=dst_port,
            src_port=src_port,
            proto="udp"
        )
    print("Sending SIP OPTIONS from %s:%d to %s:%d with timeout %f ..." % (
        src_host, src_port, dst_host, dst_port, args.sock_timeout)
    )
    if args.verbose_mode:
        print("Full request:")
        print(request)
    start_time = time.time()
    resp, length, error = send_function(
        dst_host=dst_host,
        request=request,
        dst_port=dst_port,
        src_host=src_host,
        src_port=src_port,
        timeout=args.sock_timeout
    )
    end_time = time.time()
    rtt_time = end_time - start_time
    if error:
        print("Error occured: %s" % str(error))
        exit(1)
    else:
        print("Response from %s (%d bytes, %f sec RTT): %s" % (
            dst_host,
            length,
            rtt_time,
            resp.split("\n")[0].strip()
            )
        )
        if args.verbose_mode:
            print("Full response:")
            print(resp)
        print("\n\n")
        exit(0)


if __name__ == "__main__":
    main()
