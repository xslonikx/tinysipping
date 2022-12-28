#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
tinysipping is a small tool that sends SIP OPTIONS requests to remote host and
reads responses.
Written in Python2.7-compatible style without external dependencies
for CentOS 7 compatibility.
"""

import socket
import uuid
import random
import argparse
import time
import re
import platform
import ssl

from abc import abstractmethod

from socket import SOL_SOCKET, SOL_IP, SO_REUSEADDR, SO_REUSEPORT, \
    SOCK_DGRAM, SOCK_STREAM, AF_INET, gethostbyname, gethostname

VERSION = "0.1.2"
TOOL_DESCRIPTION = "tinysipping is small tool that sends SIP OPTIONS " \
                   "requests to remote host and reads responses. "

MAX_FORWARDS = 70  # times
DFL_PING_TIMEOUT = 1.0  # seconds
MAX_RECVBUF_SIZE = 1400  # bytes
DFL_SIP_PORT = 5060
DFL_REQS_COUNT = 0
DFL_SIP_TRANSPORT = "udp"
RTT_INFINITE = 99999999.0
DFL_SEND_PAUSE = 0.5
DFL_PAYLOAD_SIZE = 600  # bytes
DFL_FROM_USER = "tinysipping"
DFL_TO_USER = "options"
DFL_TLS_SEC_LEVEL = 3
FAIL_EXIT_CODE = 1

CA_PATH_DARWIN = "/etc/ssl/cert.pem"
CA_PATH_LINUX = "/etc/ssl/certs/ca-certificates.crt"   # Debian/Ubuntu path. Temporary path

WEAK_CIPHERS = (
    "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES256-SHA:GOST2012256-GOST89-GOST89:"
    "DHE-RSA-CAMELLIA256-SHA:GOST2001-GOST89-GOST89:AES256-SHA:CAMELLIA256-SHA:ECDHE-RSA-AES128-SHA:"
    "ECDHE-ECDSA-AES128-SHA:DHE-RSA-AES128-SHA:DHE-RSA-CAMELLIA128-SHA:AES128-SHA:CAMELLIA128-SHA:"
    "ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
    "EDH-RSA-DES-CBC3-SHA:DES-CBC3-SHA"
)

DEFAULT_CIPHERS = (
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:"
    "ECDHE-ECDSA-AES256-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-RSA-CAMELLIA256-SHA256:"
    "AES256-GCM-SHA384:AES256-SHA256:CAMELLIA256-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-CAMELLIA128-SHA256:AES128-GCM-SHA256:"
    "AES128-SHA256:CAMELLIA128-SHA256"
)

ALL_CIPHERS = "{}:{}".format(WEAK_CIPHERS, DEFAULT_CIPHERS)

# Unfortunately, Python2.7 has no these definitions in socket module
# Linux-specific definitions, taken from Linux in.h file
IP_MTU_DISCOVER = 10
IP_PMTUDISC_DONT = 0  # Never send DF frames
IP_PMTUDISC_WANT = 1  # Use per route hints
IP_PMTUDISC_DO = 2  # Always DF
IP_PMTUDISC_PROBE = 3  # Ignore dst pmtu

# length of this phrase * 1489 = totally 65536 bytes -- it's max theoretical size of UDP dgram
PADDING_PATTERN = "the_quick_brown_fox_jumps_over_the_lazy_dog_" * 1489

# messages templates for further formatting
MSG_SENDING_REQS = "Sending {} SIP OPTIONS request{} (size {}) {}to {}:{} with timeout {:.03f}s..."
MSG_RESP_FROM = "SEQ #{} ({} bytes sent) {}: Response from {} ({} bytes, {:.03f} sec RTT): {}"
MSG_DF_BIT_NOT_SUPPORTED = "WARNING: ignoring dont_set_df_bit (-m) option that is not supported by this platform"
MSG_UNABLE_TO_CONNECT = "FATAL: Unable to connect to {}:{}: {}"

SPLIT_URI_REGEX = re.compile(
    "(?:(?P<user>[\w\.]+):?(?P<password>[\w\.]+)?@)?"
    "\[?(?P<host>(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|"
    "(?:(?:[0-9a-fA-F]{1,4}):){7}[0-9a-fA-F]{1,4}|"
    "(?:(?:[0-9A-Za-z]+\.)+[0-9A-Za-z]+))\]?:?(?P<port>\d{1,6})?"
)


def singleton(cls):
    instances = {}

    def getinstance():
        if cls not in instances:
            instances[cls] = cls()
        return instances[cls]
    return getinstance


@singleton
class Config:
    dst_host = ""  # value is to be filled below
    dst_port = DFL_SIP_PORT  # value may be redefined below
    bind_addr = ""
    bind_port = 0
    count = 0
    timeout = DFL_PING_TIMEOUT
    proto = "udp"
    verbose_mode = False
    bad_resp_is_fail = False
    pause_between_transmits = DFL_SEND_PAUSE
    payload_size = DFL_PAYLOAD_SIZE
    dont_set_df_bit = False
    from_user = DFL_FROM_USER
    to_user = DFL_TO_USER
    tls_sec_level = DFL_TLS_SEC_LEVEL
    from_domain = None    # will be set later
    to_domain = None   # will be set later
    ca_certs_path = ssl.get_default_verify_paths().cafile
    fail_count = None
    fail_perc = None

    def __init__(self, args=None):
        self._get_params_from_args(self._prepare_argv_parser().parse_args())

    @staticmethod
    def _prepare_argv_parser():
        """
        (for internal use) Returns ArgumentParser with configured options and \
        help strings
        :returns: (argparse.ArgumentParser) object with cli options
        """
        ap = argparse.ArgumentParser(
            description=TOOL_DESCRIPTION,
            formatter_class=lambda prog: argparse.HelpFormatter(prog, width=120)
        )

        exit_nonzero_opts = ap.add_mutually_exclusive_group(required=False)
        tls_opts = ap.add_argument_group(title="TLS Options", description="make sense only with TLS protocol")
        sip_uri_opts = ap.add_argument_group(title="Custom SIP URI options")

        ap.add_argument(
            "destination",
            help="Destination host <dst>[:port] (default port {})".format(DFL_SIP_PORT),
            type=str,
            action="store",
        )

        ap.add_argument(
            "-c",
            dest="count",
            help="Number of requests, 0 for infinite ping (default)",
            type=int,
            default=DFL_REQS_COUNT
        )

        ap.add_argument(
            "-f",
            dest="bad_resp_is_fail",
            help="Treat 4xx, 5xx, 6xx responses as failure (default no)",
            action="store_true"
        )

        ap.add_argument(
            "-i",
            dest="src_sock",
            help="Source iface [ip/hostname]:[port] (hostname part is optional, possible to type \":PORT\" form "
                 "to just set srcport)",
            type=str,
            action="store"
        )

        exit_nonzero_opts.add_argument(
            "-k",
            dest="fail_perc",
            help="Program exits with non-zero code if percentage of failed requests more than threshold",
            type=float,
            action="store",
        )

        exit_nonzero_opts.add_argument(
            "-K",
            dest="fail_count",
            help="Program exits with non-zero code if count of failed requests more than threshold",
            type=int,
            action="store",
        )

        ap.add_argument(
            "-l",
            dest="pause_between_transmits",
            help="Pause between transmits (default 0.5, 0 for immediate send)",
            action="store",
            type=float,
            default=DFL_SEND_PAUSE
        )

        ap.add_argument(
            "-m",
            dest="dont_set_df_bit",
            help="Do not set DF bit (default DF bit is set) "
                 "- currently works only on Linux",
            action="store_true",
        )

        ap.add_argument(
            "-p",
            dest="proto",
            help="Protocol (udp, tcp, tls)",
            type=str,
            action="store",
            choices=["tcp", "udp", "tls"],
            default=DFL_SIP_TRANSPORT,
        )

        sip_uri_opts.add_argument(
            "-Rf",
            dest="field_from",
            help="SIP From: and Contact: URI",
            type=str,
            action="store",
        )

        sip_uri_opts.add_argument(
            "-Rt",
            dest="field_to",
            help="SIP To: and R-URI",
            type=str,
            action="store",
        )

        ap.add_argument(
            "-s",
            dest="payload_size",
            help="Fill request up to certain size",
            type=int,
            action="store",
            default=DFL_PAYLOAD_SIZE
        )

        ap.add_argument(
            "-t",
            dest="sock_timeout",
            help="Socket timeout in seconds (float, default {:.01f})".format(DFL_PING_TIMEOUT),
            type=float,
            action="store",
            default=DFL_PING_TIMEOUT
        )

        tls_opts.add_argument(
            "-Tl",
            dest="tls_sec_level",
            choices=[0, 1, 2, 3, 4, 5],
            help="OpenSSL security level - more is secure. Zero means enabling all insecure ciphers",
            type=int,
            action="store",
            default=3
        )

        tls_opts.add_argument(
            "-Tc",
            dest="ca_certs_path",
            help="Custom CA certificates path",
            type=str,
            action="store",
        )

        ap.add_argument(
            "-v",
            dest="verbose_mode",
            help="Verbose mode (show sent and received content)",
            action="store_true"
        )

        ap.add_argument("-V", action="version", version=VERSION)
        return ap

    def _get_params_from_args(self, args):
        """
        (for internal use only)
        Function returns dictionary with params taken from args.
        Dictionary content:
        {
            "dst_host": (str) Destination host. Assertion for not empty
            "dst_port": (int) Destination port.
            "bind_addr": (str) Source interface ip
            "bind_port": (int) Source port
            "count": (int) Count of requests that are to be sent
            "timeout": (float) Socket timeout
            "proto": Protocol (tcp or udp). Assertion for proto in (tcp, udp)
            "verbose_mode": (bool) Verbose mode
            "bad_resp_is_fail": (bool) Treat 4xx, 5xx, 6xx responses as fail
        }
        :param args: (argparse.Namespace) argparse CLI arguments
        :return: (dict) dictionary with params
        """
        self.count = args.count
        self.timeout = args.sock_timeout
        self.proto = args.proto
        self.verbose_mode = args.verbose_mode
        self.bad_resp_is_fail = args.bad_resp_is_fail
        self.pause_between_transmits = args.pause_between_transmits
        self.payload_size = args.payload_size
        self.dont_set_df_bit = args.dont_set_df_bit
        self.tls_sec_level = args.tls_sec_level

        try:
            self.fail_count = args.fail_count
        except AttributeError:
            pass

        try:
            self.fail_perc = args.fail_perc
        except AttributeError:
            pass

        assert args.destination is not None
        if ":" in args.destination:
            self.dst_host, dst_port = args.destination.split(":")
            self.dst_port = int(dst_port)
        else:
            self.dst_host = args.destination

        if args.src_sock:
            if ":" in args.src_sock:
                self.bind_addr, bind_port = args.src_sock.split(":")
                self.bind_port = int(bind_port)
            else:
                self.bind_addr = args.src_sock

        # hc means hosts contact
        # is to be used as domain part if we have no exact From: domain
        hc = self.bind_addr if self.bind_addr else gethostname()

        if args.field_from:
            uri_components = SPLIT_URI_REGEX.search(args.field_from)
            if uri_components:
                fu, _, fd, fp = uri_components.groups()  # ignoring password part
                if fu:
                    self.from_user = fu

                # this block allows input string in "xxx@" format with empty user part
                # in this case domain part will be empty after pattern matching.
                # We take it from hostname or source interface address
                # so, you're able to have constant user part and variable domain part
                if not fd:
                    fd = hc
                self.from_domain = "{}:{}".format(fd, fp) if fp else fd
        else:
            self.from_domain = "{}:{}".format(hc, self.bind_port) if self.bind_port else hc

        if args.field_to:
            uri_components = SPLIT_URI_REGEX.search(args.field_to)
            if uri_components:
                tu, _, td, tp = uri_components.groups()  # ignoring password part
                if tu:
                    self.to_user = tu

                # As similar block above, this one allows input To: URI value in "xxx@" format with empty domain part
                if not td:
                    td = self.dst_host

                self.to_domain = "{}:{}".format(td, tp) if tp else td
        elif self.dst_port:
            self.to_domain = "{}:{}".format(self.dst_host, self.dst_port)
        else:
            self.to_domain = self.dst_host

        if not self.ca_certs_path:
            if platform.system() == "Darwin":
                self.ca_certs_path = CA_PATH_DARWIN
            elif platform.system() == "Linux":
                self.ca_certs_path = CA_PATH_LINUX


class AbstractWorker(object):
    def __init__(self):
        self.c = Config()
        self._sock = None
        self._create_sock()  # overload this in children
        self._configure_socket()

    @abstractmethod
    def _create_sock(self):
        pass

    def _configure_socket(self):
        self._sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self._sock.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        self._sock.settimeout(self.c.timeout)

        # better use ipaddress lib for this check, but, sadly, it's not always available out-of-box on centos7
        bind_addr = self.c.bind_addr if not self.c.bind_addr.startswith("127.") else ""
        self._sock.bind((bind_addr, self.c.bind_port))

        # Sending packets with DF bit set is default application behavior

        # small platform-specific notices
        # df bit often set on linux systems because pmtu discovery often enabled by default
        # but better not to rely on it and explicitly set and unset this
        if self.c.dont_set_df_bit:
            if platform.system() == "Linux":
                self._sock.setsockopt(SOL_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT)
        else:
            if platform.system() == "Linux":
                self._sock.setsockopt(SOL_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
            else:
                # for possible future work
                pass

    def close(self):
        self._sock.close()

    @abstractmethod
    def send(self, req):
        pass

    def __del__(self):
        self.close()


class TCPWorker(AbstractWorker):
    def __init__(self):
        super(TCPWorker, self).__init__()
        self._sock.connect((self.c.dst_host, self.c.dst_port))

    def _create_sock(self):
        self._sock = socket.socket(AF_INET, SOCK_STREAM)

    def send(self, req):
        """
        Function performs single sending of SIP packet
        :param req: (str) data to send
        :returns: tuple(string, int, exc/None) - buffer and length
        """
        try:
            self._sock.sendall(req.encode())
            raw = self._sock.recv(MAX_RECVBUF_SIZE)
            data = raw.decode(encoding="utf-8", errors="ignore")
            return data, len(raw), None
        except (socket.timeout, socket.error) as e:
            return "", 0, e


class UDPWorker(AbstractWorker):
    def _create_sock(self):
        self._sock = socket.socket(AF_INET, SOCK_DGRAM)

    def send(self, req):
        """
        Function performs single sending of SIP packet
        :param req: (str) data to send
        :returns: tuple(str, int, exc/None) - buffer, length and possible err
        """
        dstip = gethostbyname(self.c.dst_host)
        try:
            bin_req = req.encode()
            self._sock.sendto(bin_req, (dstip, self.c.dst_port))
            while True:
                raw, addr = self._sock.recvfrom(MAX_RECVBUF_SIZE)
                rhost, rport = addr
                if (rhost == dstip) and (rport == self.c.dst_port):
                    data = raw.decode(encoding="utf-8", errors="ignore")
                    return data, len(raw), None
        except (socket.timeout, socket.error) as e:
            return "", 0, e


class TLSWorker(TCPWorker):
    def _create_sock(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        ctx.minimum_version = ssl.PROTOCOL_TLSv1_2
        ctx.set_ciphers(ALL_CIPHERS)
        # TODO: write platform-independent method
        ctx.load_verify_locations(cafile=self.c.ca_certs_path)
        self._s = socket.socket(AF_INET, SOCK_STREAM)
        server_host_name = "{}:{}".format(self.c.dst_host, self.c.dst_port)
        self._sock = ctx.wrap_socket(self._s, server_hostname=server_host_name)


def create_sip_req():
    """
    Generates serialized SIP header from source data
    :params (dict): dict with parameters of request
    :returns: (string): SIP header in human-readable format. Don"t forget to
                        encode it to bytes
    """
    c = Config()
    # sender_contact will be used in Via: and Contact: headers
    # sc_host = sender contact's host part
    sc_host = c.bind_addr if c.bind_addr else gethostname()
    sender_contact = "{}:{}".format(sc_host, c.bind_port) if c.bind_port else sc_host

    call_id = "{0}-{1}".format(gethostname(), str(uuid.uuid4()))

    # According to RFC3261, the branch ID MUST always begin with the characters
    # "z9hG4bK". It used as magic cookie. Beyond this requirement, the precise
    # format of the branch token is implementation-defined
    branch_id = "z9hG4bK{}".format(str(uuid.uuid4()))

    # these intervals are chosen to keep request size always constant
    cseq = random.randint(1000000000, 2147483647)
    tag_id = random.randint(1000000000, 2147483647)

    # HeaDeR WithOut padding
    hdr_wo_padding = "\r\n".join([
        "OPTIONS sip:{}@{} SIP/2.0".format(c.to_user, c.to_domain),
        "Via: SIP/2.0/{} {};branch={};rport".format(c.proto.upper(), sender_contact, branch_id),
        "Max-Forwards: {}".format(MAX_FORWARDS),
        "To: <sip:{}@{}>".format(c.to_user, c.to_domain),
        "From: <sip:{}@{}>;tag={}".format(c.from_user, c.from_domain, tag_id),
        "Call-ID: {}".format(call_id),
        "CSeq: {} OPTIONS".format(cseq),
        "Contact: <sip:{}@{}>;transport={}".format(c.from_user, sender_contact, c.proto.lower()),
        "Accept: application/sdp",
        "Content-Length: 0",
        "P-tinysipping-padding: {}",  # this field will be filled later
        "\r\n"  # for getting double \r\n at the end, as it need by RFC
    ])

    # original hdr_wo_padding has length with {} symbols accounted, so when we substitute padding,
    # we lose two these symbols and get actual length 2 bytes less than expected
    padding_size = c.payload_size - len(hdr_wo_padding) + 2 if c.payload_size else 0
    padding = PADDING_PATTERN[:padding_size] if padding_size > 0 else ""
    request = hdr_wo_padding.format(padding)
    return request


def _debug_print(*strings):
    """
    (for internal use only)
    Prints strings only if verbosity is on. Use it any time when you want to
    toggle messages output.
    :param verbose: (bool) Enables verbosity. If false, nothing will be printed
    :param strings: (list) list of strings
    """
    c = Config()
    if c.verbose_mode:
        for s in strings:
            print(s)


def send_one_request(worker, request, bad_resp_is_fail=True):
    """
    Function sends one SIP OPTIONS request, receives the response and returns
    results
    :param worker: (AbstractWorker) worker
    :param request: (string) Data is to be sent
    :param bad_resp_is_fail: (bool) treat response code >4xx as error or not
    :returns: (dict) results
    """
    result = {
        "is_successful": True,
        "length": 0,
        "error": None,  # exception for further handling
        "rtt": -1.0,  # round trip time
        "brief_response": "",  # just heading string like SIP/2.0 200 OK
        "resp_code": 0,  # response code
        "full_response": "",
    }

    start_time = time.time()
    full_response, length, error = worker.send(req=request)
    end_time = time.time()

    if error:
        result["is_successful"] = False
        result["error"] = error
        result["brief_response"] = str(error)
    else:
        result["full_response"] = full_response
        result["length"] = length
        result["brief_response"] = full_response.split("\n")[0].strip()
        result["resp_code"] = int(result["brief_response"].split(" ")[1])
        result["rtt"] = end_time - start_time
        if bad_resp_is_fail and result["resp_code"] >= 400:
            result["is_successful"] = False
    return result


def calculate_stats(results):
    """
    Calculates overall statistics with RTT, response codes etc.
    :param results: (list) list of dicts with results of single test
    :returns: (dict) overall statistics
    """
    min_rtt = RTT_INFINITE
    max_rtt = 0.0
    total_rtt_sum = 0.0
    passed_requests = 0
    failed_requests = 0
    answered_requests = 0
    response_codes = {}
    socket_error_causes = {}
    total_requests = len(results)

    for i in results:
        if i["is_successful"]:
            passed_requests += 1
        else:
            failed_requests += 1

        if i["rtt"] >= 0:
            min_rtt = i["rtt"] if (i["rtt"] < min_rtt) else min_rtt
            max_rtt = i["rtt"] if (i["rtt"] > max_rtt) else max_rtt
            total_rtt_sum += i["rtt"]

        try:
            response_codes[int(i["resp_code"])] += 1
        except KeyError:  # it means there"s no such response code before
            response_codes[int(i["resp_code"])] = 1

        if i["error"]:
            cause_name = re.sub(r"\s+", "_", str(i["error"])).lower()
            try:
                socket_error_causes[cause_name] += 1
            except KeyError:  # it means there"s no such response code before
                socket_error_causes[cause_name] = 1
        else:
            answered_requests += 1

    try:
        del response_codes[0]  # 0 is a stub response code
    except KeyError:
        pass

    avg_rtt = -1.0 if not answered_requests else float(total_rtt_sum) / float(answered_requests)

    answered_perc = float(answered_requests) * 100.0 / float(total_requests)
    failed_perc = float(failed_requests) * 100.0 / float(total_requests)
    passed_perc = 100.0 - failed_perc

    return {
        "total": total_requests,
        "passed": passed_requests,
        "failed": failed_requests,
        "failed_perc": failed_perc,
        "passed_perc": passed_perc,
        "answered": answered_requests,
        "answered_perc": answered_perc,
        "min_rtt": -1.0 if min_rtt == RTT_INFINITE else min_rtt,
        "max_rtt": max_rtt,
        "avg_rtt": avg_rtt,
        "response_codes": response_codes,
        "socket_error_causes": socket_error_causes,
    }


def pretty_print_stats(stats):
    """
    Just prints statistics in pretty form
    :param stats: (dict) statistics
    """
    perc_fmt = "{:15s} {:5d} / {:0.3f}%"
    float_value_str = "{:15s} {:9.3f}"

    total_requests = stats["total"]

    print("\n")
    print("------ FINISH -------")
    print("{:15s} {:5d}".format("Total requests:", total_requests))
    print(perc_fmt.format("Answered:", stats["answered"], stats["answered_perc"]))
    print(perc_fmt.format("Passed:", stats["passed"], stats["passed_perc"]))
    print(perc_fmt.format("Failed:", stats["failed"], stats["failed_perc"]))

    print("\n")

    if stats["answered"]:
        print("RTT stats (in ms):")
        print(float_value_str.format("min.RTT:", stats["min_rtt"]))
        print(float_value_str.format("avg.RTT:", stats["avg_rtt"]))
        print(float_value_str.format("max.RTT:", stats["max_rtt"]))
        print("\n")

    if stats["socket_error_causes"]:
        print("Socket errors causes stats:")
        for k, v in stats["socket_error_causes"].items():
            cause_percentage = 100.0 * (float(v) / float(total_requests))
            print("{:15s} {:5s}/{:0.3f}%".format(str(k), str(v), cause_percentage))
        print("\n")

    if stats["response_codes"]:
        print("Response codes stats:")
        for k, v in stats["response_codes"].items():
            resp_code_percentage = 100.0 * (float(v) / float(total_requests))
            print(perc_fmt.format(str(k), v, resp_code_percentage))


def send_sequential_req_with_print(worker, seq_num):
    """
    Wrapper around send_one_request() with progress messages printing
    :param worker: (AbstractWorker) worker
    :param seq_num: (int) current sequence number
    :return: (dict) results
    """
    c = Config()
    request = create_sip_req()

    result = send_one_request(worker, request, c.bad_resp_is_fail)
    _msg_resp = MSG_RESP_FROM.format(
        seq_num,
        len(request),
        "PASS" if result["is_successful"] else "FAIL",
        c.dst_host,
        result["length"],
        result["rtt"],
        result["brief_response"],
    )
    print(_msg_resp)
    _debug_print("Full request:", request)
    _debug_print("Full response:", result["full_response"])
    _debug_print("{}\n".format("-" * len(_msg_resp)))
    return result


def get_worker():
    c = Config()
    assert c.proto in ("tcp", "udp", "tls")
    if c.proto == "tcp":
        return TCPWorker()
    elif c.proto == "udp":
        return UDPWorker()
    elif c.proto == "tls":
        return TLSWorker()


def main():
    """
    void main( void )
    """
    c = Config()

    if c.dont_set_df_bit and platform.system() != "Linux":
        print(MSG_DF_BIT_NOT_SUPPORTED)

    results = []

    # Sent from <host:port> substring. Places into resulting message if
    # <src_interface>:<port> was specified
    _from_msg = "" if not c.bind_addr and not c.bind_port else "from {}:{} ".format(c.bind_addr, c.bind_port)

    sending_req_msg = MSG_SENDING_REQS.format(
        "infinitely" if not c.count else c.count,
        "" if c.count == 1 else "s",
        c.payload_size,
        _from_msg,
        c.dst_host,
        c.dst_port,
        c.timeout
    )

    print(sending_req_msg)
    print("{}\n".format("-" * len(sending_req_msg)))

    try:
        worker = get_worker()
    except (socket.error, socket.timeout) as e:
        print(MSG_UNABLE_TO_CONNECT.format(c.dst_host, c.dst_port, str(e)))
        exit(FAIL_EXIT_CODE)

    seq = 0
    try:
        if not c.count:  # 0 means infinite ping
            while True:
                result = send_sequential_req_with_print(worker, seq)
                results.append(result)
                seq += 1
                if c.pause_between_transmits:
                    time.sleep(c.pause_between_transmits)
        else:
            for seq in range(0, c.count):
                result = send_sequential_req_with_print(worker, seq)
                results.append(result)
                if c.pause_between_transmits:
                    time.sleep(c.pause_between_transmits)
    except KeyboardInterrupt:
        print("\nInterrupted after {} request{}".format(seq, "" if seq == 1 else "s"))

    stats = calculate_stats(results)
    pretty_print_stats(stats)

    fail_count_triggered = c.fail_count is not None and stats["failed"] > c.fail_count
    fail_perc_triggered = c.fail_perc is not None and stats["failed_perc"] > c.fail_perc
    exit_code = FAIL_EXIT_CODE if fail_count_triggered or fail_perc_triggered else 0

    exit(exit_code)


if __name__ == "__main__":
    main()