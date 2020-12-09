# tinysipping
Tiny SIP Ping - Small script which can perform simple SIP OPTIONS ping and read 
response.  
Deliberately written in Python2.7-compatible style without any external 
dependencies for CentOS 7 compatibility.  

```
Usage:
positional arguments:
  destination           Destination host <dst>[:port] (default port 5060)

optional arguments:
  -h, --help            show this help message and exit
  -c COUNT              Number of requests, 0 for infinite ping (default)
  -p {tcp,udp}          Protocol (udp or tcp)
  -t SOCK_TIMEOUT       Socket timeout in seconds (float, default 1.0)
  -f                    Treat 4xx, 5xx, 6xx responses as failed request
  -l PAUSE_BETWEEN_TRANSMITS
                        Pause between transmits (default 0.5, 0 for immediate send)
  -i SRC_SOCK           Source iface [ip/hostname]:[port] (hostname part is optional, possible to type ":PORT" form to
                        just set srcport)
  -v                    Verbose mode (show sent and received content)
  -s PAYLOAD_SIZE       Fill request upto certain size
  -V                    show program's version number and exit
```
