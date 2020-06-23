package collector

import (
	"log"
	"sync"

	"github.com/bvantagelimited/freeradius_exporter/client"
	"github.com/prometheus/client_golang/prometheus"
)

// FreeRADIUSCollector type.
type FreeRADIUSCollector struct {
	client *client.FreeRADIUSClient
	// indicates if we could reach freeradius or not
	up    *prometheus.Desc
	mutex sync.Mutex
}

// NewFreeRADIUSCollector creates an FreeRADIUSCollector.
func NewFreeRADIUSCollector(cl *client.FreeRADIUSClient) *FreeRADIUSCollector {
	return &FreeRADIUSCollector{
		client: cl,
		up: prometheus.NewDesc(
			"freeradius_up", "Boolean gauge of 1 if freeradius was reachable, or 0 if not", []string{}, nil),
	}
}

// Describe outputs metrics descriptions.
func (f *FreeRADIUSCollector) Describe(ch chan<- *prometheus.Desc) {
	// nothing
}

// Collect fetches metrics from and sends them to the provided channel.
func (f *FreeRADIUSCollector) Collect(ch chan<- prometheus.Metric) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	allStats, err := f.client.Stats()
	if err != nil {
		log.Println(err)
		ch <- prometheus.MustNewConstMetric(f.up, prometheus.GaugeValue, float64(0))
		return
	}
	ch <- prometheus.MustNewConstMetric(f.up, prometheus.GaugeValue, float64(1))

	for _, stats := range allStats {
		ch <- stats
	}
}
