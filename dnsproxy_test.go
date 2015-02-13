package main

import (
	"dns"
	"testing"
)

const (
	nameserver = "127.0.0.1:53"
	domain     = "ur.gd"
)

func BenchmarkDig(b *testing.B) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	c := new(dns.Client)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Exchange(m, nameserver)
	}

}
