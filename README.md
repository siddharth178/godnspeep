# godnspeep
spy on the DNS queries your computer is making

This is quick and dirty port of [idea shared](http://jvns.ca/blog/2021/03/31/dnspeep-tool/) by [Julia Evans](https://twitter.com/b0rk). She wrote it in rust, I thought giving it a try in go could be fun and will get a chance to peek at [gopacket](https://github.com/google/gopacket). This into [blog post](https://itnext.io/sniffing-creds-with-go-a-journey-with-libpcap-73bc3e74966) about gopacket came in real handy.


## How to use it

Get the package
```
go get github.com/siddharth178/godnspeep
```

Run it as sudo
```
sudo ~/go/bin/godnspeep 
Usage: godnspeep <device>

Output columns:
query:     DNS query type (A, CNAME, etc)
name:      Hostname the DNS query is requesting
server IP: IP address of the DNS server the query was made to
elapsed:   How long the DNS response took to arrive (by looking at question packet and answer packet)
response:  Responses from the Answer section of the DNS response (or \"<no response>\" if none was found).
			Multiple responses are separated by commas.
```

Sample output
```
$ sudo ~/go/bin/godnspeep wlp4s0
query, name, server, elapsed, response
AAAA, connectivity-check.ubuntu.com, 8.8.8.8, 80.314197ms, ""
AAAA, connectivity-check.ubuntu.com, 8.8.8.8, 31.648021ms, ""
A, i2-glxgptfahkpmbwnqbgfesftigikzjv.init.cedexis-radar.net, 8.8.8.8, 352.019833ms, "103.84.152.178"
A, rum14.perf.linkedin.com, 8.8.8.8, 32.086546ms, "CNAME www-linkedin-com.l-0005.l-msedge.net,CNAME l-0005.l-msedge.net,13.107.42.14"
A, rum20.perf.linkedin.com, 8.8.8.8, 64.376822ms, "CNAME mix.linkedin.com,CNAME glb-na.mix.linkedin.com,CNAME pop-esv5.mix.linkedin.com,108.174.11.37"
```
