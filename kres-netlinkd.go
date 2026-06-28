package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/apex/log"
	"github.com/kvaster/apexutils"

	"github.com/kvaster/kres-netlinkd/netlinkd"
)

var socketPath = flag.String("socket", "/run/kres-netlinkd.sock", "unix socket path to listen on")
var family = flag.String("family", "inet", "nftables table family (inet/ip/ip6)")
var table = flag.String("table", "route", "nftables table name")
var setPrefix = flag.String("set-prefix", "blocked-", "prefix of the ipv4 set name")
var setPrefix6 = flag.String("set-prefix6", "blocked6-", "prefix of the ipv6 set name")

func main() {
	flag.Parse()
	apexutils.ParseFlags()

	log.Info("starting kres-netlinkd")

	s := netlinkd.New(netlinkd.Config{
		SocketPath: *socketPath,
		Family:     *family,
		Table:      *table,
		SetPrefix:  *setPrefix,
		SetPrefix6: *setPrefix6,
	})

	if err := s.Start(); err != nil {
		log.WithError(err).Error("error starting kres-netlinkd")
		os.Exit(1)
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	<-stopChan

	log.Info("stopping kres-netlinkd")
	s.Stop()

	log.Info("stopped kres-netlinkd")
}
