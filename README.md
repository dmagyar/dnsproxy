# dnsproxy
DNS Filtering proxy and minimalistic nameserver in GO

- Recurse only A, AAAA, CNAME records (onlyipq)
- Filter on domain suffix (suffixes)
- Filter on returned IP (ipfilter)
- Swap NXDOMAIN with static A response and set TTL (swapnxdip, swapnxdttl)
- Hosts file lookup for static (override) entries 

Based on DNS library (github.com/miekg/dns)

# Installation

- Install golang, set GOPATH, get dependent libraries
-- go get github.com/miekg/dns
-- go get github.com/BurntSushi/toml
- Build application
-- go build -o dnsproxy *.go

See dnsproxy.conf for examples
