# tinysipping
Tiny SIP Ping - Small script which can perform simple SIP OPTIONS ping and read 
response.  
Deliberately written in Python2.7-compatible style without any external 
dependencies for CentOS 7 compatibility.  
Also, it was quite minified for comfortable
copypasting to REPL sacrificing some PEP-8 recommedations..    

```
usage: tinysipping.py [-h] -d DST_SOCK [-p {tcp,udp}] [-t SOCK_TIMEOUT]
                  [-s SRC_SOCK] [-v] [-V]  

optional arguments:  
-h, --help       show this help message and exit  
-p {tcp,udp}     Protocol ('udp' or 'tcp')  
-t SOCK_TIMEOUT  Socket timeout in seconds (float, default 10.0)  
-s SRC_SOCK      Source iface [ip/hostname]:[port] (hostname part is  
                 optional, possible to type ":PORT" form to just set  
                 srcport)  
-v               Verbose mode (show sent and received content)  
-V               show program's version number and exit  

mandatory arguments:  
-d DST_SOCK      Destination host <ip/hostname>[:port]  

```