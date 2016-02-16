package main

import (
	"bufio"
	"net"
	"os"
	"regexp"
	"strings"
)

type Hosts struct {
	FileHosts  map[string]string
}

func NewHosts(hs HostsSettings) Hosts {
	fileHosts := &FileHosts{hs.HostsFile}
	hosts := Hosts{fileHosts.GetAll()}
	return hosts

}

/*
1. Resolve hosts file only one times
2. Match local /etc/hosts file first
*/

func (h *Hosts) Get(domain string, family int) (ip net.IP, ok bool) {
	var sip string

	if sip, ok = h.FileHosts[strings.ToLower(domain)]; !ok {
			return nil, false
	}

	switch family {
	case _IP4Query:
		ip = net.ParseIP(sip).To4()
		return ip, (ip != nil)
	case _IP6Query:
		ip = net.ParseIP(sip).To16()
		return ip, (ip != nil)
	}
	return nil, false
}

func (h *Hosts) GetAll() map[string]string {

	m := make(map[string]string)
	for domain, ip := range h.FileHosts {
		m[domain] = ip
	}
	return m
}

type FileHosts struct {
	file string
}

func (f *FileHosts) GetAll() map[string]string {
	var hosts = make(map[string]string)

	buf, err := os.Open(f.file)
	if err != nil {
		panic("Can't open " + f.file)
	}

	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {

		line := scanner.Text()
		line = strings.TrimSpace(strings.ToLower(line))

		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		sli := strings.Split(line, " ")
		if len(sli) == 1 {
			sli = strings.Split(line, "\t")
		}

		if len(sli) < 2 {
			continue
		}

		domain := sli[len(sli)-1]
		ip := sli[0]
		if !f.isDomain(domain) || !f.isIP(ip) {
			continue
		}

		hosts[domain] = ip
	}
	return hosts
}

func (f *FileHosts) isDomain(domain string) bool {
	if f.isIP(domain) {
		return false
	}
	match, _ := regexp.MatchString("^[a-zA-Z0-9][a-zA-Z0-9-]", domain)
	return match
}

func (f *FileHosts) isIP(ip string) bool {
	return (net.ParseIP(ip) != nil)
}
