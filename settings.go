package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
)

var (
	settings Settings
)

type Settings struct {
	Version      string
	Debug        bool
	Server       DNSServerSettings `toml:"server"`
	ResolvConfig ResolvSettings    `toml:"resolv"`
	Log          LogSettings       `toml:"log"`
	Cache        CacheSettings     `toml:"cache"`
	Hosts        HostsSettings     `toml:"hosts"`
	Filters	     FilterSettings    `toml:"filters"`
}

type ResolvSettings struct {
	ResolvFile string `toml:"resolv-file"`
	Timeout    int
}

type DNSServerSettings struct {
	Host string
	Port int
}

type DBSettings struct {
	Host     string
	Port     int
	DB       int
	Password string
}

func (s DBSettings) Addr() string {
	return s.Host + ":" + strconv.Itoa(s.Port)
}

type LogSettings struct {
	File string
}

type CacheSettings struct {
	Backend  string
	Expire   int
	Maxcount int
}

type HostsSettings struct {
	Enable      bool
	HostsFile   string `toml:"host-file"`
	TTL         uint32 `toml:"ttl"`
}

type FilterSettings struct {
	OnlyIPQ	    bool	`toml:"onlyipq"`
	Suffixes    []string	`toml:"suffixes"`
	IPFilter    []string	`toml:"ipfilter"`
	SwapNXDIP   string	`toml:"swapnxdip"`
	SwapNXDTTL  uint32	`toml:"swapnxdttl"`
}

func init() {

	var configFile string

	flag.StringVar(&configFile, "c", "dnsproxy.conf", "Look for dnsproxy toml-formatting config file in this directory")
	flag.Parse()

	if _, err := toml.DecodeFile(configFile, &settings); err != nil {
		fmt.Printf("%s is not a valid toml config file\n", configFile)
		fmt.Println(err)
		os.Exit(1)
	}

}
