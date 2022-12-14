# tinysipping
Tiny SIP Ping - Small script which can perform simple SIP OPTIONS ping and read 
response.  
Deliberately written in Python2.7-compatible style without any external 
dependencies for CentOS 7 compatibility.  

```
positional arguments:
  destination           Destination host <dst>[:port] (default port 5060)

optional arguments:
  -h, --help            show this help message and exit
  -c COUNT              Number of requests, 0 for infinite ping (default)
  -f                    Treat 4xx, 5xx, 6xx responses as failure (default no)
  -i SRC_SOCK           Source iface [ip/hostname]:[port] (hostname part is optional, possible to type ":PORT" form to
                        just set srcport)
  -k FAIL_PERC          Program exits with non-zero code if percentage of failed requests more than threshold
  -K FAIL_COUNT         Program exits with non-zero code if count of failed requests more than threshold
  -l PAUSE_BETWEEN_TRANSMITS
                        Pause between transmits (default 0.5, 0 for immediate send)
  -m                    Do not set DF bit (default DF bit is set) - currently works only on Linux
  -p {tcp,udp}          Protocol (udp, tcp)
  -Rf FIELD_FROM        SIP From: URI
  -Rt FIELD_TO          SIP To: and R-URI
  -s PAYLOAD_SIZE       Fill request up to certain size
  -t SOCK_TIMEOUT       Socket timeout in seconds (float, default 1.0)
  -v                    Verbose mode (show sent and received content)
  -V                    show program's version number and exit
```
