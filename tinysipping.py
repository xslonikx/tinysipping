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

from abc import abstractmethod

from socket import SOL_SOCKET, SOL_IP, SO_REUSEADDR, SO_REUSEPORT, \
    IPPROTO_IP, SOCK_DGRAM, SOCK_STREAM, AF_INET, \
    gethostbyname, gethostname

if platform.system() == "Linux":
    from socket import IP_MTU_DISCOVER, IP_PMTUDISC_DO

VERSION = "0.1.1"
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
DFL_PAYLOAD_SIZE = 600   # bytes
FAIL_EXIT_CODE = 1

# totally 65536 bytes - max theoretical size of UDP dgram
PADDING_PATTERN = "the_quick_brown_fox_jumps_over_the_lazy_dog_" * 1489

# messages templates for further formatting
MSG_SENDING_REQS = "Sending {} SIP OPTIONS request{} (size {}) {}to " \
                   "{}:{} with timeout {:.03f}s..."
MSG_RESP_FROM = "SEQ #{} ({} bytes sent) {}: Response from {} ({} bytes, " \
                "{:.03f} sec RTT): {}"


class AbstractWorker:
    def __init__(self, params):
        self._params = params
        self._sock = None
        self._create_sock()   # overload this in children
        self._configure_socket()

    @abstractmethod
    def _create_sock(self):
        pass

    def _configure_socket(self):
        self._sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self._sock.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        self._sock.settimeout(self._params["timeout"])
        # better use ipaddress lib for this check, but, sadly, it's not always
        # available out-of-box on centos7
        bind_addr = self._params["bind_addr"] \
            if not self._params["bind_addr"].startswith("127.") \
            else ""
        self._sock.bind((bind_addr, self._params["bind_port"]))

        # we have DF bit set by default, that's why double negation
        if not self._params["dont_set_df_bit"]:
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
    def _create_sock(self):
        self._sock = socket.socket(AF_INET, SOCK_STREAM)

    def send(self, req):
        """
        Function performs single sending of SIP packet
        :param req: (str) data to send
        :returns: tuple(string, int, exc/None) - buffer and length
        """
        try:
            self._sock.connect((self._params["dst_host"],
                                self._params["dst_port"]))
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
        dstip = gethostbyname(self._params["dst_host"])
        try:
            bin_req = req.encode()
            self._sock.sendto(bin_req, (dstip, self._params["dst_port"]))
            while True:
                raw, addr = self._sock.recvfrom(MAX_RECVBUF_SIZE)
                rhost, rport = addr
                if (rhost == dstip) and (rport == self._params["dst_port"]):
                    data = raw.decode(encoding="utf-8", errors="ignore")
                    return data, len(raw), None
        except (socket.timeout, socket.error) as e:
            return "", 0, e

    def close(self):
        """
        Method just closes the underlying socket
        """
        self._sock.close()


class TLSWorker(TCPWorker):
    pass


def gen_padding(size=DFL_PAYLOAD_SIZE):
    """
    Returns padding for SIP header or body
    :param size: (int) size of padding
    :return: (str) prepared padding
    """
    return PADDING_PATTERN[:size]


def create_sip_req(dst_host, dst_port=DFL_SIP_PORT, bind_port=0,
                   proto=DFL_SIP_TRANSPORT, request_size=DFL_PAYLOAD_SIZE):
    """
    Generates serialized SIP header from source data
    :param bind_port: (int) source port. Used in From: header
    :param dst_port: (int) destination port. Used in URI and To: header
    :param dst_host: (str) ip address or hostname of remote side.
    :param proto: (str) tcp or udp, otherwise ValueError will raise
    :param request_size: (int) size that request should be padded to.
    :returns: (string): SIP header in human-readable format. Don"t forget to
                        encode it to bytes
    """
    my_hostname = gethostname()
    call_id = "{0}-{1}".format(my_hostname, str(uuid.uuid4()))

    # According to RFC3261, the branch ID MUST always begin with the characters
    # "z9hG4bK". It used as magic cookie. Beyond this requirement, the precise
    # format of the branch token is implementation-defined
    branch_id = "z9hG4bK{}".format(str(uuid.uuid4()))

    # these intervals are chosen to keep request size always constant
    cseq = random.randint(1000000000, 2147483647)
    tag_id = random.randint(1000000000, 2147483647)

    # HeaDeR WithOut
    hdr_wo_padding = "\r\n".join([
        "OPTIONS sip:options@{}:{} SIP/2.0".format(dst_host, dst_port),
        "Via: SIP/2.0/{} {};branch={};rport".format(
            proto.upper(), my_hostname, branch_id
        ),
        "Max-Forwards: {}".format(MAX_FORWARDS),
        "To: <sip:options@{}:{}>".format(dst_host, dst_port),
        "From: <sip:options@{}:{}>;tag={}".format(
            my_hostname, bind_port, tag_id
        ),
        "Call-ID: {}".format(call_id),
        "CSeq: {} OPTIONS".format(cseq),
        "Contact: <sip:tinysipping@{}>".format(my_hostname),
        "Accept: application/sdp",
        "Content-Length: 0",
        "P-tinysipping-padding: {}",   # this field will be filled later
        "\r\n"  # for getting double \r\n at the end, as it need by RFC
    ])

    padding_size = request_size - len(hdr_wo_padding) + 2
    padding = gen_padding(padding_size) if padding_size > 0 else ""
    request = hdr_wo_padding.format(padding)
    return request


def _get_params_from_cliargs(args):
    """
    (for internal use only)
    Function returns dictionary with params taken from cliargs.
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
        ""ad_resp_is_fail": (bool) Treat 4xx, 5xx, 6xx responses as fail
    }
    :param args: (argparse.Namespace) argparse CLI arguments
    :return: (dict) dictionary with params
    """
    params = {
        "dst_host": None,  # value is to be redefined below
        "dst_port": DFL_SIP_PORT,  # value is to be redefined below
        "bind_addr": "",
        "bind_port": 0,
        "count": args.count,
        "timeout": args.sock_timeout,
        "proto": args.proto.lower(),  # let user set TCP or tcp
        "verbose_mode": args.verbose_mode,
        "bad_resp_is_fail": args.bad_resp_is_fail,
        "pause_between_transmits": args.pause_between_transmits,
        "payload_size": args.payload_size,
        "dont_set_df_bit": args.dont_set_df_bit,
    }

    try:
        params["fail_count"] = args.fail_count
    except AttributeError:
        pass

    try:
        params["fail_perc"] = args.fail_perc
    except AttributeError:
        pass

    if ":" in args.destination:
        params["dst_host"], dst_port = args.destination.split(":")
        params["dst_port"] = int(dst_port)
    else:
        params["dst_host"] = args.destination

    if args.src_sock:
        if ":" in args.src_sock:
            params["bind_addr"], bind_port = args.src_sock.split(":")
            params["bind_port"] = int(bind_port)
        else:
            params["bind_addr"] = args.src_sock

    assert (params["proto"] in ("tcp", "udp"))  # tcp and udp support only
    assert (params["dst_host"])  # dst_host is mandatory parameter
    return params


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

    ap.add_argument(
        "destination",
        help="Destination host <dst>[:port] (default port {})".format(
            DFL_SIP_PORT),
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
        help="Source iface [ip/hostname]:[port] (hostname part is optional, "
             "possible to type \":PORT\" form to just set srcport)",
        type=str,
        action="store"
    )

    exit_nonzero_opts.add_argument(
        "-k",
        dest="fail_perc",
        help="Program exits with non-zero code if percentage of failed "
             "requests more than threshold",
        type=float,
        action="store",
    )

    exit_nonzero_opts.add_argument(
        "-K",
        dest="fail_count",
        help="Program exits with non-zero code if count of failed "
             "requests more than threshold",
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
        help="Protocol (udp, tcp)",
        type=str,
        choices=("tcp", "udp"),
        default=DFL_SIP_TRANSPORT
    )

    ap.add_argument(
        "-t",
        dest="sock_timeout",
        help="Socket timeout in seconds (float, default {:.01f})".format(
            DFL_PING_TIMEOUT),
        type=float,
        action="store",
        default=DFL_PING_TIMEOUT
    )

    ap.add_argument(
        "-v",
        dest="verbose_mode",
        help="Verbose mode (show sent and received content)",
        action="store_true"
    )

    ap.add_argument(
        "-s",
        dest="payload_size",
        help="Fill request upto certain size",
        type=int,
        action="store",
        default=DFL_PAYLOAD_SIZE
    )

    ap.add_argument("-V", action="version", version=VERSION)
    return ap


def _debug_print(verbose, *strings):
    """
    (for internal use only)
    Prints strings only if verbosity is on. Use it any time when you want to
    toggle messages output.
    :param verbose: (bool) Enables verbosity. If false, nothing will be printed
    :param strings: (list) list of strings
    """
    if verbose:
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
        "error": None,   # exception for further handling
        "rtt": -1.0,   # round trip time
        "brief_response": "",   # just heading string like SIP/2.0 200 OK
        "resp_code": 0,   # response code
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
    successful_requests = 0
    failed_requests = 0
    answered_requests = 0
    response_codes = {}
    socket_error_causes = {}
    total_requests = len(results)

    for i in results:
        if i["is_successful"]:
            successful_requests += 1
        else:
            failed_requests += 1

        if i["rtt"] >= 0:
            min_rtt = i["rtt"] if (i["rtt"] < min_rtt) else min_rtt
            max_rtt = i["rtt"] if (i["rtt"] > max_rtt) else max_rtt
            total_rtt_sum += i["rtt"]

        try:
            response_codes[int(i["resp_code"])] += 1
        except KeyError:    # it means there"s no such response code before
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
        del response_codes[0]   # 0 is a stub response code
    except KeyError:
        pass

    avg_rtt = -1.0 if not answered_requests \
        else float(total_rtt_sum) / float(answered_requests)

    answered_perc = float(answered_requests) * 100.0 / float(total_requests)
    failed_perc = float(failed_requests) * 100.0 / float(total_requests)
    passed_perc = 100.0 - failed_perc

    return {
        "total": total_requests,
        "successful": successful_requests,
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
    perc_fmt_str = "{:15s} {:5d}/{:0.3f}%"
    float_value_str = "{:15s} {:9.3f}"

    total_requests = stats["total"]

    print("\n")
    print("------ FINISH -------")
    print("{:15s} {:5d}".format("Total requests:", total_requests))
    print(perc_fmt_str.format("Answered:", stats["answered"], stats["answered_perc"]))
    print(perc_fmt_str.format("Successful:", stats["successful"], stats["passed_perc"]))
    print(perc_fmt_str.format("Failed:", stats["failed"], stats["failed_perc"]))

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
            print("{:15s} {:5s}/{:0.3f}%".format(
                str(k),
                str(v),
                cause_percentage)
            )
        print("\n")

    if stats["response_codes"]:
        print("Response codes stats:")
        for k, v in stats["response_codes"].items():
            resp_code_percentage = 100.0 * (float(v) / float(total_requests))
            print(perc_fmt_str.format(str(k), v,  resp_code_percentage))


def send_sequential_req_with_print(worker, seq_num, params):
    """
    Wrapper around send_one_request() with progress messages printing
    :param worker: (AbstractWorker) worker
    :param seq_num: (int) current sequence number
    :param params: (dict) parameters
    :return: (dict) results
    """
    request = create_sip_req(
        dst_host=params["dst_host"],
        dst_port=params["dst_port"],
        bind_port=params["bind_port"],
        proto=params["proto"],
        request_size=params["payload_size"]
    )
    bad_resp_is_fail = params["bad_resp_is_fail"]

    result = send_one_request(worker, request, bad_resp_is_fail)
    _msg_resp = MSG_RESP_FROM.format(
        seq_num,
        len(request),
        "PASS" if result["is_successful"] else "FAIL",
        params["dst_host"],
        result["length"],
        result["rtt"],
        result["brief_response"],
    )
    print(_msg_resp)
    _debug_print(params["verbose_mode"], "Full request:", request)
    _debug_print(
        params["verbose_mode"],
        "Full response:",
        result["full_response"]
    )
    _debug_print(params["verbose_mode"],"{}\n".format("-" * len(_msg_resp)))
    return result


def get_worker(params):
    assert params["proto"] in ("tcp", "udp")
    if params["proto"] == "tcp":
        return TCPWorker(params)
    elif params["proto"] == "udp":
        return UDPWorker(params)


def main():
    """
    void main( void )
    """
    params = _get_params_from_cliargs(_prepare_argv_parser().parse_args())

    if params["dont_set_df_bit"] and platform.system() != "Linux":
        print("Warning - ignoring dont_set_df_bit (-m) option that is not "
              "supported by this platform")

    print("DEBUG::: ", params)
    results = []
    worker = get_worker(params)

    # Sent from <host:port> substring. Places into resulting message if
    # <src_interface>:<port> was specified
    _from_substr = "" if not params["bind_addr"] and not params["bind_port"] \
        else "from {}:{} ".format(params["bind_addr"], params["bind_port"])
    sending_req_msg = MSG_SENDING_REQS.format(
        "infinitely" if not params["count"] else params["count"],
        "" if params["count"] == 1 else "s",
        params["payload_size"],
        _from_substr,
        params["dst_host"],
        params["dst_port"],
        params["timeout"]
    )
    print(sending_req_msg)
    print("{}\n".format("-" * len(sending_req_msg)))

    seq = 0
    try:
        if not params["count"]:   # 0 means infinite ping
            while True:
                result = send_sequential_req_with_print(worker, seq, params)
                results.append(result)
                seq += 1
                if params["pause_between_transmits"]:
                    time.sleep(params["pause_between_transmits"])
        else:
            for seq in range(0, params["count"]):
                result = send_sequential_req_with_print(worker, seq, params)
                results.append(result)
                if params["pause_between_transmits"]:
                    time.sleep(params["pause_between_transmits"])
    except KeyboardInterrupt:
        print("\nInterrupted after {} request{}".format(
            seq, "" if seq == 1 else "s")
        )

    stats = calculate_stats(results)
    pretty_print_stats(stats)

    f_c_triggered = "fail_count" in params.keys() \
                    and stats["failed"] > params["fail_count"]

    f_p_triggered = "fail_perc" in params.keys() \
                    and stats["failed_perc"] > params["fail_perc"]

    exit_code = FAIL_EXIT_CODE if f_p_triggered or f_c_triggered else 0
    exit(exit_code)


if __name__ == "__main__":
    main()
