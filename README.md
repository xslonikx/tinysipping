# tinysipping
Tiny SIP Ping - tool for manual pinging SIP services by SIP OPTIONS requests.  
Deliberately written in Python2.7-compatible style without any external dependecies
for compatibility with basic Centos7.x installation.    
  
Also, some PEP-8 rules was sacrificed for comfortable copypasting to REPL.

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