# tinysipping
Tiny SIP Ping - Small script which can perform simple SIP OPTIONS ping and read 
response.  
Deliberately written in Python2.7-compatible style without any external 
dependencies for CentOS 7 compatibility.  
Also, it was quite minified for comfortable
copypasting to REPL sacrificing some PEP-8 recommedations..    

```
Usage: 
positional arguments:
  destination      Destination host <dst>[:port] (default port 5060)

optional arguments:
  -h, --help       show this help message and exit
  -c COUNT         Count of requests (default 1, 0 for infinite ping)
  -p {tcp,udp}     Protocol ('udp' or 'tcp')
  -t SOCK_TIMEOUT  Socket timeout in seconds (float, default 10.0)
  -f               Treat 4xx, 5xx, 6xx responses as failed request
  -s SRC_SOCK      Source iface [ip/hostname]:[port] (hostname part is optional, possible to type ":PORT" form to just
                   set srcport)
  -v               Verbose mode (show sent and received content)
  -V               show program's version number and exit
```