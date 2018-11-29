package collector

import (
	"log"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/bvantagelimited/freeradius_exporter/client"
)

// FreeRADIUSCollector type.
type FreeRADIUSCollector struct {
	client  *client.FreeRADIUSClient
	metrics map[string]*prometheus.Desc
	mutex   sync.Mutex
}

// NewFreeRADIUSCollector creates an FreeRADIUSCollector.
func NewFreeRADIUSCollector(cl *client.FreeRADIUSClient) *FreeRADIUSCollector {
	return &FreeRADIUSCollector{
		client: cl,
		metrics: map[string]*prometheus.Desc{
			"freeradius_total_access_requests":               prometheus.NewDesc("freeradius_total_access_requests", "Total access requests", nil, nil),
			"freeradius_total_access_accepts":                prometheus.NewDesc("freeradius_total_access_accepts", "Total access accepts", nil, nil),
			"freeradius_total_access_rejects":                prometheus.NewDesc("freeradius_total_access_rejects", "Total access rejects", nil, nil),
			"freeradius_total_access_challenges":             prometheus.NewDesc("freeradius_total_access_challenges", "Total access challenges", nil, nil),
			"freeradius_total_auth_responses":                prometheus.NewDesc("freeradius_total_auth_responses", "Total auth responses", nil, nil),
			"freeradius_total_auth_duplicate_requests":       prometheus.NewDesc("freeradius_total_auth_duplicate_requests", "Total auth duplicate requests", nil, nil),
			"freeradius_total_auth_malformed_requests":       prometheus.NewDesc("freeradius_total_auth_malformed_requests", "Total auth malformed requests", nil, nil),
			"freeradius_total_auth_invalid_requests":         prometheus.NewDesc("freeradius_total_auth_invalid_requests", "Total auth invalid requests", nil, nil),
			"freeradius_total_auth_dropped_requests":         prometheus.NewDesc("freeradius_total_auth_dropped_requests", "Total auth dropped requests", nil, nil),
			"freeradius_total_auth_unknown_types":            prometheus.NewDesc("freeradius_total_auth_unknown_types", "Total auth unknown types", nil, nil),
			"freeradius_total_proxy_access_requests":         prometheus.NewDesc("freeradius_total_proxy_access_requests", "Total proxy access requests", nil, nil),
			"freeradius_total_proxy_access_accepts":          prometheus.NewDesc("freeradius_total_proxy_access_accepts", "Total proxy access accepts", nil, nil),
			"freeradius_total_proxy_access_rejects":          prometheus.NewDesc("freeradius_total_proxy_access_rejects", "Total proxy access rejects", nil, nil),
			"freeradius_total_proxy_access_challenges":       prometheus.NewDesc("freeradius_total_proxy_access_challenges", "Total proxy access challenges", nil, nil),
			"freeradius_total_proxy_auth_responses":          prometheus.NewDesc("freeradius_total_proxy_auth_responses", "Total proxy auth responses", nil, nil),
			"freeradius_total_proxy_auth_duplicate_requests": prometheus.NewDesc("freeradius_total_proxy_auth_duplicate_requests", "Total proxy auth duplicate requests", nil, nil),
			"freeradius_total_proxy_auth_malformed_requests": prometheus.NewDesc("freeradius_total_proxy_auth_malformed_requests", "Total proxy auth malformed requests", nil, nil),
			"freeradius_total_proxy_auth_invalid_requests":   prometheus.NewDesc("freeradius_total_proxy_auth_invalid_requests", "Total proxy auth invalid requests", nil, nil),
			"freeradius_total_proxy_auth_dropped_requests":   prometheus.NewDesc("freeradius_total_proxy_auth_dropped_requests", "Total proxy auth dropped requests", nil, nil),
			"freeradius_total_proxy_auth_unknown_types":      prometheus.NewDesc("freeradius_total_proxy_auth_unknown_types", "Total proxy auth unknown types", nil, nil),
			"freeradius_total_acct_requests":                 prometheus.NewDesc("freeradius_total_acct_requests", "Total acct requests", nil, nil),
			"freeradius_total_acct_responses":                prometheus.NewDesc("freeradius_total_acct_responses", "Total acct responses", nil, nil),
			"freeradius_total_acct_duplicate_requests":       prometheus.NewDesc("freeradius_total_acct_duplicate_requests", "Total acct duplicate requests", nil, nil),
			"freeradius_total_acct_malformed_requests":       prometheus.NewDesc("freeradius_total_acct_malformed_requests", "Total acct malformed requests", nil, nil),
			"freeradius_total_acct_invalid_requests":         prometheus.NewDesc("freeradius_total_acct_invalid_requests", "Total acct invalid requests", nil, nil),
			"freeradius_total_acct_dropped_requests":         prometheus.NewDesc("freeradius_total_acct_dropped_requests", "Total acct dropped requests", nil, nil),
			"freeradius_total_acct_unknown_types":            prometheus.NewDesc("freeradius_total_acct_unknown_types", "Total acct unknown types", nil, nil),
			"freeradius_total_proxy_acct_requests":           prometheus.NewDesc("freeradius_total_proxy_acct_requests", "Total proxy acct requests", nil, nil),
			"freeradius_total_proxy_acct_responses":          prometheus.NewDesc("freeradius_total_proxy_acct_responses", "Total proxy acct responses", nil, nil),
			"freeradius_total_proxy_acct_duplicate_requests": prometheus.NewDesc("freeradius_total_proxy_acct_duplicate_requests", "Total proxy acct duplicate requests", nil, nil),
			"freeradius_total_proxy_acct_malformed_requests": prometheus.NewDesc("freeradius_total_proxy_acct_malformed_requests", "Total proxy acct malformed requests", nil, nil),
			"freeradius_total_proxy_acct_invalid_requests":   prometheus.NewDesc("freeradius_total_proxy_acct_invalid_requests", "Total proxy acct invalid requests", nil, nil),
			"freeradius_total_proxy_acct_dropped_requests":   prometheus.NewDesc("freeradius_total_proxy_acct_dropped_requests", "Total proxy acct dropped requests", nil, nil),
			"freeradius_total_proxy_acct_unknown_types":      prometheus.NewDesc("freeradius_total_proxy_acct_unknown_types", "Total proxy acct unknown types", nil, nil),
		},
	}
}

// Describe outputs metrics descriptions.
func (f *FreeRADIUSCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range f.metrics {
		ch <- m
	}
}

// Collect fetches metrics from and sends them to the provided channel.
func (f *FreeRADIUSCollector) Collect(ch chan<- prometheus.Metric) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	stats, err := f.client.Stats()
	if err != nil {
		log.Printf("Error fetching stats: %v", err)
		return
	}

	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_access_requests"], prometheus.CounterValue, float64(stats.Access.Requests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_access_accepts"], prometheus.CounterValue, float64(stats.Access.Accepts))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_access_rejects"], prometheus.CounterValue, float64(stats.Access.Rejects))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_access_challenges"], prometheus.CounterValue, float64(stats.Access.Challenges))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_responses"], prometheus.CounterValue, float64(stats.Auth.Responses))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_duplicate_requests"], prometheus.CounterValue, float64(stats.Auth.DuplicateRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_malformed_requests"], prometheus.CounterValue, float64(stats.Auth.MalformedRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_invalid_requests"], prometheus.CounterValue, float64(stats.Auth.InvalidRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_dropped_requests"], prometheus.CounterValue, float64(stats.Auth.DroppedRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_unknown_types"], prometheus.CounterValue, float64(stats.Auth.UnknownTypes))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_access_requests"], prometheus.CounterValue, float64(stats.ProxyAccess.Requests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_access_accepts"], prometheus.CounterValue, float64(stats.ProxyAccess.Accepts))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_access_rejects"], prometheus.CounterValue, float64(stats.ProxyAccess.Rejects))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_access_challenges"], prometheus.CounterValue, float64(stats.ProxyAccess.Challenges))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_responses"], prometheus.CounterValue, float64(stats.ProxyAuth.Responses))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_duplicate_requests"], prometheus.CounterValue, float64(stats.ProxyAuth.DuplicateRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_malformed_requests"], prometheus.CounterValue, float64(stats.ProxyAuth.MalformedRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_invalid_requests"], prometheus.CounterValue, float64(stats.ProxyAuth.InvalidRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_dropped_requests"], prometheus.CounterValue, float64(stats.ProxyAuth.DroppedRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_unknown_types"], prometheus.CounterValue, float64(stats.ProxyAuth.UnknownTypes))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_requests"], prometheus.CounterValue, float64(stats.Accounting.Requests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_responses"], prometheus.CounterValue, float64(stats.Accounting.Responses))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_duplicate_requests"], prometheus.CounterValue, float64(stats.Accounting.DuplicateRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_malformed_requests"], prometheus.CounterValue, float64(stats.Accounting.MalformedRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_invalid_requests"], prometheus.CounterValue, float64(stats.Accounting.InvalidRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_dropped_requests"], prometheus.CounterValue, float64(stats.Accounting.DroppedRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_unknown_types"], prometheus.CounterValue, float64(stats.Accounting.UnknownTypes))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_requests"], prometheus.CounterValue, float64(stats.ProxyAccounting.Requests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_responses"], prometheus.CounterValue, float64(stats.ProxyAccounting.Responses))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_duplicate_requests"], prometheus.CounterValue, float64(stats.ProxyAccounting.DuplicateRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_malformed_requests"], prometheus.CounterValue, float64(stats.ProxyAccounting.MalformedRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_invalid_requests"], prometheus.CounterValue, float64(stats.ProxyAccounting.InvalidRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_dropped_requests"], prometheus.CounterValue, float64(stats.ProxyAccounting.DroppedRequests))
	ch <- prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_unknown_types"], prometheus.CounterValue, float64(stats.ProxyAccounting.UnknownTypes))
}
