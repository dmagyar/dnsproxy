package main

import (
	"github.com/miekg/dns"
	"strconv"
	"time"
)

type Server struct {
	host     string
	port     int
	rTimeout time.Duration
	wTimeout time.Duration
}

func (s *Server) Addr() string {
	return s.host + ":" + strconv.Itoa(s.port)
}

func (s *Server) Run() {

	Handler := NewHandler()

	udpHandler := dns.NewServeMux()
	udpHandler.HandleFunc(".", Handler.DoUDP)

	udpServer := &dns.Server{Addr: s.Addr(),
		Net:          "udp",
		Handler:      udpHandler,
		UDPSize:      65535,
		ReadTimeout:  s.rTimeout,
		WriteTimeout: s.wTimeout}

	go s.start(udpServer)
}

func (s *Server) start(ds *dns.Server) {

	logger.Printf("Start %s listener on %s\n", ds.Net, s.Addr())
	err := ds.ListenAndServe()
	if err != nil {
		logger.Fatalf("Start %s listener on %s failed:%s", ds.Net, s.Addr(), err.Error())
	}
}
