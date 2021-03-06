package main

import (
	"log"
	"os"
	"os/signal"
	"runtime"
	"time"
)

var (
	logger *log.Logger
)

func main() {

	logger = initLogger(settings.Log.File)
	server := &Server{
		host:     settings.Server.Host,
		port:     settings.Server.Port,
		rTimeout: 5 * time.Second,
		wTimeout: 5 * time.Second,
	}
	
	server.Run()
	logger.Printf("dnsproxy %s start", settings.Version)

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt)

forever:
	for {
		select {
		case <-sig:
			logger.Printf("signal received, stopping")
			break forever
		}
	}

}

func Debug(format string, v ...interface{}) {
	if settings.Debug {
		logger.Printf(format, v...)
	}
}

func initLogger(log_file string) (logger *log.Logger) {
	if log_file != "" {
		f, err := os.Create(log_file)
		if err != nil {
			os.Exit(1)
		}
		logger = log.New(f, "dnsproxy [=] ", log.Ldate|log.Ltime)
	} else {
		logger = log.New(os.Stdout, "dnsproxy [=]", log.Ldate|log.Ltime)
	}
	return logger

}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

