package main

import (
	"sync"
	"time"
	"net"
	"github.com/miekg/dns"
	"strings"
)

type Question struct {
	qname  string
	qtype  string
	qclass string
}

const (
	notIPQuery = 0
	_IP4Query  = 4
	_IP6Query  = 6
)

func (q *Question) String() string {
	return q.qname + " " + q.qclass + " " + q.qtype
}

type DNSProxyHandler struct {
	resolver *Resolver
	cache    Cache
	hosts    Hosts
	mu       *sync.Mutex
}

func NewHandler() *DNSProxyHandler {

	var (
		clientConfig *dns.ClientConfig
		cacheConfig  CacheSettings
		resolver     *Resolver
		cache        Cache
	)

	resolvConfig := settings.ResolvConfig
	clientConfig, err := dns.ClientConfigFromFile(resolvConfig.ResolvFile)
	if err != nil {
		logger.Printf(":%s is not a valid resolv.conf file\n", resolvConfig.ResolvFile)
		logger.Println(err)
		panic(err)
	}
	clientConfig.Timeout = resolvConfig.Timeout
	resolver = &Resolver{clientConfig}

	cacheConfig = settings.Cache
	switch cacheConfig.Backend {
	case "memory":
		cache = &MemoryCache{
			Backend:  make(map[string]Mesg),
			Expire:   time.Duration(cacheConfig.Expire) * time.Second,
			Maxcount: cacheConfig.Maxcount,
			mu:       new(sync.RWMutex),
		}
	default:
		logger.Printf("Invalid cache backend %s", cacheConfig.Backend)
		panic("Invalid cache backend")
	}

	hosts := NewHosts(settings.Hosts)

	return &DNSProxyHandler{resolver, cache, hosts, new(sync.Mutex)}
}

func (h *DNSProxyHandler) do(Net string, w dns.ResponseWriter, req *dns.Msg) {
	q := req.Question[0]

	if (settings.Filters.OnlyIPQ)&&(q.Qtype == dns.TypeANY) { 
		q.Qtype = dns.TypeA
	}

	Q := Question{UnFqdn(q.Name), dns.TypeToString[q.Qtype], dns.ClassToString[q.Qclass]}
	Debug("Question: %s", Q.String())

	IPQuery := h.isIPQuery(q)
	if ((IPQuery == 0)&&(settings.Filters.OnlyIPQ)) {
		Debug("Only IP queries allowed (A,AAAA)")
		m := new(dns.Msg)
		m.SetReply(req)
		// return servfail
		m.MsgHdr.Rcode = 2
		w.WriteMsg(m)
		return
	}
	
	if (len(settings.Filters.Suffixes) > 0) {
		j := -1;
		for i := range settings.Filters.Suffixes {
			Debug("Suffix: %s", settings.Filters.Suffixes[i])
			if (strings.HasSuffix(q.Name,settings.Filters.Suffixes[i])) {
				dot := "."
				dot += settings.Filters.Suffixes[i]
				if (settings.Filters.Suffixes[i][0] == '.') {
					j = i
					break
				} else if (len(q.Name) == len(settings.Filters.Suffixes[i])) {
					// exact match
					j = i
					break				 
				} else if (strings.HasSuffix(q.Name,dot)) {
					// matches '.'+suffix
					j = i
					break
				}
			}
		}
		if (j == -1) {
			Debug("Request %s does not match any suffix filter -> SRVFAIL", q.Name)
			m := new(dns.Msg)
			m.SetReply(req)
			// return servfail
			m.MsgHdr.Rcode = 2
			w.WriteMsg(m)
			return		
		} else {
			Debug("Request %s matches suffix filter %s", q.Name, settings.Filters.Suffixes[j])		
		}
	}

	// Query hosts
	if settings.Hosts.Enable && IPQuery > 0 {
		if ip, ok := h.hosts.Get(Q.qname, IPQuery); ok {
			m := new(dns.Msg)
			m.SetReply(req)

			switch IPQuery {
			case _IP4Query:
				rr_header := dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    settings.Hosts.TTL,
				}
				a := &dns.A{rr_header, ip}
				m.Answer = append(m.Answer, a)
			case _IP6Query:
				rr_header := dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    settings.Hosts.TTL,
				}
				aaaa := &dns.AAAA{rr_header, ip}
				m.Answer = append(m.Answer, aaaa)
			}

			w.WriteMsg(m)
			Debug("%s found in hosts file", Q.qname)
			return
		} else {
			Debug("%s didn't found in hosts file", Q.qname)
		}

	}

	// Only query cache when qtype == 'A' , qclass == 'IN'
	key := KeyGen(Q)
	if IPQuery > 0 {
		mesg, err := h.cache.Get(key)
		if err != nil {
			Debug("%s didn't hit cache: %s", Q.String(), err)
		} else {
			Debug("%s hit cache", Q.String())
			h.mu.Lock()
			mesg.Id = req.Id
			w.WriteMsg(mesg)
			h.mu.Unlock()
			return
		}

	}

	mesg, err := h.resolver.Lookup(Net, req)

	if (((settings.Filters.OnlyIPQ) || (len(settings.Filters.IPFilter)>0)) && (err == nil)) {
		var newans []dns.RR
		for a := range mesg.Answer {
			ah := mesg.Answer[a].Header()
			Debug("ANS[%d]: %s",a,mesg.Answer[a])
			if ((ah.Rrtype == dns.TypeA)&&(len(settings.Filters.IPFilter)>0)) {
				t, _ := mesg.Answer[a].(*dns.A)
				j := 0
				for i := range settings.Filters.IPFilter {
					if (strings.HasPrefix(t.A.String(),settings.Filters.IPFilter[i])) {
						Debug("A answer %s matches IPFilter %s", t.A.String(),settings.Filters.IPFilter[i])
						j = 1
						break
					}
				}
				if (j == 0) {
					Debug("A answer %s does not match any IPFilter -> NXD", q.Name)
					err = dns.ErrId
					break
				}
			}
			if (settings.Filters.OnlyIPQ) {
				if (ah.Rrtype == dns.TypeA)||(ah.Rrtype == dns.TypeAAAA)||(ah.Rrtype == dns.TypeCNAME) {
					newans = append(newans, mesg.Answer[a])
				}
			}
		}
		if (settings.Filters.OnlyIPQ) {
			mesg.Answer = newans
		}
	}

	if err != nil {
		if (len(settings.Filters.SwapNXDIP)>0) {
			rr_header := dns.RR_Header {
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    settings.Filters.SwapNXDTTL,
			}
			m := new(dns.Msg)
			m.SetReply(req)
			ip := net.ParseIP(settings.Filters.SwapNXDIP).To4()
			a := &dns.A{rr_header, ip}
			m.Answer = append(m.Answer, a)
			m.MsgHdr.Authoritative = true
			w.WriteMsg(m)
			return

		} else {
			Debug("%s", err)
			dns.HandleFailed(w, req)
			return
		}
	}
	w.WriteMsg(mesg)

	if IPQuery > 0 && len(mesg.Answer) > 0 {
		err = h.cache.Set(key, mesg)

		if err != nil {
			Debug("Set %s cache failed: %s", Q.String(), err.Error())
		}

		Debug("Insert %s into cache", Q.String())
	}
}

func (h *DNSProxyHandler) DoTCP(w dns.ResponseWriter, req *dns.Msg) {
	h.do("tcp", w, req)
}

func (h *DNSProxyHandler) DoUDP(w dns.ResponseWriter, req *dns.Msg) {
	h.do("udp", w, req)
}

func (h *DNSProxyHandler) isIPQuery(q dns.Question) int {
	if q.Qclass != dns.ClassINET {
		return notIPQuery
	}

	switch q.Qtype {
	case dns.TypeA:
		return _IP4Query
	case dns.TypeAAAA:
		return _IP6Query
	default:
		return notIPQuery
	}
}

func UnFqdn(s string) string {
	if dns.IsFqdn(s) {
		return s[:len(s)-1]
	}
	return s
}
