#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
tinysipping is a small tool that sends SIP OPTIONS requests to remote host and
reads responses.
Written in Python2.7-compatible style without external dependencies
for CentOS 7 compatibility. Also, it was quite minified for comfortable
copypasting to REPL sacrificing some PEP-8 recommedations.
"""

import socket
import uuid
import random
import argparse
import time
import re

VERSION = "0.0.4"
TOOL_DESCRIPTION = "tinysipping is small tool that sends SIP OPTIONS " \
                   "requests to remote host and reads responses. "

MAX_FORWARDS = 70  # times
PING_TIMEOUT = 10.0  # seconds
MAX_RECVBUF_SIZE = 1400  # bytes
DFL_SIP_PORT = 5060
DFL_REQS_COUNT = 0
DFL_SIP_TRANSPORT = "udp"
RTT_INFINITE = 99999999.0
DFL_SEND_PAUSE = 0.5

# messages templates for further formatting
MSG_SENDING_REQS = "Sending %s SIP OPTIONS request%s from %s:%d to " \
                   "%s:%d with timeout %.03fs..."
MSG_RESP_FROM = "SEQ #%d %s: Response from %s (%d bytes, %f sec RTT): %s"


def create_sip_req(dst_host, dst_port=DFL_SIP_PORT, src_port=0,
                   proto=DFL_SIP_TRANSPORT):
    """
    Generates serialized SIP header from source data
    :param src_port: (int) source port. Used in From: header
    :param dst_port: (int) destination port. Used in URI and To: header
    :param dst_host: (str) ip address or hostname of remote side.
    :param proto: (str) tcp or udp, otherwise ValueError will raise
    :returns: (string): SIP header in human-readable format. Don"t forget to
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
        "Contact: <sip:options@%s>" % my_hostname,
        "Accept: application/sdp"
        "Content-Length: 0",
        "\r\n"  # for getting double \r\n at the end, as it need by RFC
    ])


def create_socket(proto=DFL_SIP_TRANSPORT, bind_addr="", bind_port=0,
                  timeout=PING_TIMEOUT):
    """
    Function returns preconfigured socket for transport needs
    :param bind_addr: (str) source host or ip of interface (default "")
    :param bind_port: (int) source port (default 0)
    :param proto: (str) transport protocol - "tcp" or "udp"
    :param timeout: (float) socket timeout
    :return: (socket.socket) socket prepared for transmission
    """
    sock_type = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
    sock = socket.socket(socket.AF_INET, sock_type)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    if bind_addr.startswith("127."):  # checking for loopback ip.
        sock.bind(("", bind_port))
    else:
        sock.bind((bind_addr, bind_port))
    sock.settimeout(timeout)
    return sock


def udp_send(request, params):
    """
    Function performs single sending of SIP packet
    :param request: (str) data to send
    :param params: params dict. See _get_params_from_cliargs() for
    dictionary format
    :returns: tuple(string, int, exc/None) - buffer, length and possible error
    """
    dst_ipaddr = socket.gethostbyname(params["dst_host"])
    sock = create_socket(
        proto="udp",
        bind_addr=params["src_host"],
        bind_port=params["src_port"],
        timeout=params["timeout"]
    )
    try:
        sock.sendto(request.encode(), (dst_ipaddr, params["dst_port"]))
        while True:
            data, addr = sock.recvfrom(MAX_RECVBUF_SIZE)
            remote_host, remote_port = addr
            if remote_host == dst_ipaddr and remote_port == params["dst_port"]:
                return data.decode(encoding="utf-8", errors="ignore"), \
                       len(data), \
                       None
    except (socket.timeout, socket.error) as e:
        return "", 0, e
    finally:
        sock.close()


def tcp_send(request, params):
    """
    Function performs single sending of SIP packet
    :param request: (str) data to send
    :param params: params dict. See _get_params_from_cliargs() for
    dictionary format
    :returns: tuple(string, int, exc/None) - buffer and length
    """
    sock = create_socket(
        proto="tcp",
        bind_addr=params["src_host"],
        bind_port=params["src_port"],
        timeout=params["timeout"]
    )
    try:
        sock.connect((params["dst_host"], params["dst_port"]))
        sock.sendall(request.encode())
        data = sock.recv(MAX_RECVBUF_SIZE)
        return data.decode(encoding="utf-8", errors="ignore"), len(data), None
    except (socket.timeout, socket.error) as e:
        return "", 0, e
    finally:
        sock.close()


def _get_params_from_cliargs(args):
    """
    (for internal use only)
    Function returns dictionary with params taken from cliargs.
    Dictionary content:
    {
        "dst_host": (str) Destination host. Assertion for not empty
        "dst_port": (int) Destination port.
        "src_host": (str) Source interface ip
        "src_port": (int) Source port
        "count": (int) Count of requests that are to be sent
        "timeout": (float) Socket timeout
        "proto": Protocol (tcp or udp). Assertion for proto in (tcp, udp)
        "verbose_mode": (bool) Verbose mode
        ""bad_resp_is_fail"": (bool) Treat 4xx, 5xx, 6xx responses as fail
    }
    :param args: (argparse.Namespace) argparse CLI arguments
    :return: (dict) dictionary with params
    """
    params = {
        "dst_host": None,  # value is to be redefined below
        "dst_port": DFL_SIP_PORT,  # value is to be redefined below
        "src_host": "",
        "src_port": 0,
        "count": args.count,
        "timeout": args.sock_timeout,
        "proto": args.proto.lower(),  # let user set TCP or tcp
        "verbose_mode": args.verbose_mode,
        "bad_resp_is_fail": args.bad_resp_is_fail,
        "pause_between_transmits": args.pause_between_transmits,
    }
    if ":" in args.destination:
        params["dst_host"], dst_port = args.destination.split(":")
        params["dst_port"] = int(dst_port)
    else:
        params["dst_host"] = args.destination
    if args.src_sock:
        if ":" in args.src_sock:
            params["src_host"], src_port = args.src_sock.split(":")
            params["src_port"] = int(src_port)
        else:
            params["src_host"] = args.src_sock
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
    ap.add_argument(
        "destination",
        help="Destination host <dst>[:port] (default port %d)" % DFL_SIP_PORT,
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
        "-p",
        dest="proto",
        help="Protocol (udp or tcp)",
        type=str,
        choices=("tcp", "udp"),
        default=DFL_SIP_TRANSPORT
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
        "-f",
        dest="bad_resp_is_fail",
        help="Treat 4xx, 5xx, 6xx responses as failed request",
        action="store_true"
    )
    ap.add_argument(
        "-l",
        dest="pause_between_transmits",
        help="Pause between transmits (default 0.5. 0 for immediate send)",
        action="store",
        type=float,
        default=DFL_SEND_PAUSE
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


def send_one_request(request, params):
    """
    Function sends one SIP OPTIONS request, receives the response and returns
    results
    :param request: (string) Data is to be sent
    :param params: (dict) params dict. See _get_params_from_cliargs() for
    dictionary format
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
    ping_func = tcp_send if params["proto"] == "tcp" else udp_send
    start_time = time.time()
    full_response, length, error = ping_func(request=request, params=params)
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
        if params["bad_resp_is_fail"] and result["resp_code"] >= 400:
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
    return {
        "total": total_requests,
        "successful": successful_requests,
        "failed": failed_requests,
        "answered": answered_requests,
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
    total_requests = stats["total"]
    answered_percentage = 0.0 if not stats["answered"] \
        else (float(stats["answered"]) / float(total_requests))*100.0
    success_percentage = 0.0 if not stats["successful"] \
        else (float(stats["successful"]) / float(total_requests))*100.0
    failed_percentage = 0.0 if not stats["failed"] \
        else (float(stats["failed"]) / float(total_requests))*100.0
    print("\n")
    print("------ FINISH -------")
    print("Total requests:          %5d" % total_requests)
    print(
        "Answered requests:       %5d / %0.3f %%" % (
            stats["answered"],
            answered_percentage
        )
    )
    print(
        "Successful requests:     %5d / %0.3f %%" % (
            stats["successful"],
            success_percentage
        )
    )
    print(
        "Failed requests:         %5d / %0.3f %%" % (
            stats["failed"],
            failed_percentage
        )
    )
    print("\n")
    if stats["answered"]:
        print("RTT stats:")
        print("min.RTT: %0.3f" % stats["min_rtt"])
        print("avg.RTT: %0.3f" % stats["avg_rtt"])
        print("max.RTT: %0.3f" % stats["max_rtt"])
        print("\n")
    if stats["socket_error_causes"]:
        print("Socket errors causes stats:")
        for k, v in stats["socket_error_causes"].items():
            cause_percentage = 100.0 * (float(v) / float(total_requests))
            print("%3s: %6s / %0.3f %%" % (k, v, cause_percentage))
        print("\n")
    if stats["response_codes"]:
        print("Response codes stats:")
        for k, v in stats["response_codes"].items():
            resp_code_percentage = 100.0 * (float(v) / float(total_requests))
            print("%3d: %6d / %0.3f" % (k, v,  resp_code_percentage))


def send_sequential_req_with_print(seq_num, params):
    """
    Wrapper around send_one_request() with progress messages printing
    :param seq_num: (int) current sequence number
    :param params: (dict) parameters
    :return: (dict) results
    """
    request = create_sip_req(
        dst_host=params["dst_host"],
        dst_port=params["dst_port"],
        src_port=params["src_port"],
        proto=params["proto"],
    )
    result = send_one_request(request, params)
    print(MSG_RESP_FROM % (
        seq_num,
        "PASS" if result["is_successful"] else "FAIL",
        params["dst_host"],
        result["length"],
        result["rtt"],
        result["brief_response"],
        )
    )
    _debug_print(params["verbose_mode"], "Full request:", request)
    _debug_print(
        params["verbose_mode"],
        "Full response:",
        result["full_response"]
    )
    return result


def main():
    """
    void main( void )
    """
    params = _get_params_from_cliargs(_prepare_argv_parser().parse_args())
    results = []
    print(MSG_SENDING_REQS % (
        "infinitely" if not params["count"] else params["count"],
        "" if params["count"] == 1 else "s",
        params["src_host"],
        params["src_port"],
        params["dst_host"],
        params["dst_port"],
        params["timeout"]
        )
    )
    try:
        if not params["count"]:   # 0 means infinite ping
            seq = 0
            while True:
                result = send_sequential_req_with_print(seq, params)
                results.append(result)
                seq += 1
                if params["pause_between_transmits"]:
                    time.sleep(params["pause_between_transmits"])
        else:
            for seq in range(0, params["count"]):
                result = send_sequential_req_with_print(seq, params)
                results.append(result)
                if params["pause_between_transmits"]:
                    time.sleep(params["pause_between_transmits"])
    except KeyboardInterrupt:
        print("\nInterrupted after %d request%s" %
              (seq, "" if seq == 1 else "s"))
    pretty_print_stats(calculate_stats(results))
    exit(0)


if __name__ == "__main__":
    main()
