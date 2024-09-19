package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/peterbourgon/ff/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/bvantagelimited/freeradius_exporter/client"
	"github.com/bvantagelimited/freeradius_exporter/collector"
)

var version, commit, date string

func main() {
	fs := flag.NewFlagSet("freeradius_exporter", flag.ContinueOnError)
	appHelp := fs.Bool("help", false, "Display help")
	appVersion := fs.Bool("version", false, "Display version information")
	_ = fs.String("config", "", "Config file (optional)")

	listenAddr := fs.String("web.listen-address", ":9812", "Address to listen on for web interface and telemetry.")
	metricsPath := fs.String("web.telemetry-path", "/metrics", "A path under which to expose metrics.")
	radiusTimeout := fs.Int("radius.timeout", 5000, "Timeout, in milliseconds [RADIUS_TIMEOUT].")
	radiusAddr := fs.String("radius.address", "127.0.0.1:18121", "Address of FreeRADIUS status server [RADIUS_ADDRESS].")
	homeServers := fs.String("radius.homeservers", "", "List of FreeRADIUS home servers to check, e.g. '172.28.1.2:1812:auth,172.28.1.3:1813:acct' [RADIUS_HOMESERVERS].")
	radiusSecret := fs.String("radius.secret", "adminsecret", "FreeRADIUS client secret [RADIUS_SECRET].")

	err := ff.Parse(fs, os.Args[1:], ff.WithEnvVarNoPrefix(), ff.WithConfigFileFlag("config"), ff.WithConfigFileParser(ff.JSONParser))
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	if *appHelp {
		fs.PrintDefaults()
		os.Exit(0)
	}

	if *appVersion {
		println(filepath.Base(os.Args[0]), version, commit, date)
		os.Exit(0)
	}

	registry := prometheus.NewRegistry()

	hs := strings.Split(*homeServers, ",")

	radiusClient, err := client.NewFreeRADIUSClient(*radiusAddr, hs, *radiusSecret, *radiusTimeout)
	if err != nil {
		log.Fatal(err)
	}

	registry.MustRegister(collector.NewFreeRADIUSCollector(radiusClient))

	http.Handle(*metricsPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>FreeRADIUS Exporter</title></head>
			<body>
			<h1>FreeRADIUS Exporter</h1>
			<p><a href='` + *metricsPath + `'>Metrics</a></p>
			</body>
			</html>`))
	})

	srv := &http.Server{}
	listener, err := net.Listen("tcp4", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Providing metrics at %s%s", *listenAddr, *metricsPath)
	log.Fatal(srv.Serve(listener))
}
