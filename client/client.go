package client

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bvantagelimited/freeradius_exporter/freeradius"
	"github.com/prometheus/client_golang/prometheus"
	"layeh.com/radius"
	"layeh.com/radius/rfc2869"
)

// Statistics type.
type Statistics struct {
	Error           string
	Access          Access
	Auth            Auth
	ProxyAccess     Access
	ProxyAuth       Auth
	Accounting      Accounting
	ProxyAccounting Accounting
	Internal        Internal
	Server          Server
}

// Server specific stats.
type Server struct {
	OutstandingRequests uint32
	State               uint32
	TimeOfDeath         time.Time
	TimeOfLife          time.Time
	LastPacketRecv      time.Time
	LastPacketSent      time.Time
	StartTime           time.Time
	HUPTime             time.Time
	EmaWindow           uint32
	EmaUsecWindow1      uint32
	EmaUsecWindow10     uint32
	QueuePPSIn          uint32
	QueuePPSOut         uint32
	QueueUsePercentage  uint32
}

// Access type.
type Access struct {
	Requests   uint32
	Accepts    uint32
	Rejects    uint32
	Challenges uint32
}

// Auth type.
type Auth struct {
	Responses         uint32
	DuplicateRequests uint32
	MalformedRequests uint32
	InvalidRequests   uint32
	DroppedRequests   uint32
	UnknownTypes      uint32
}

// Accounting type.
type Accounting struct {
	Requests          uint32
	Responses         uint32
	DuplicateRequests uint32
	MalformedRequests uint32
	InvalidRequests   uint32
	DroppedRequests   uint32
	UnknownTypes      uint32
}

// Internal type.
type Internal struct {
	QueueLenInternal uint32
	QueueLenProxy    uint32
	QueueLenAuth     uint32
	QueueLenAcct     uint32
	QueueLenDetail   uint32
}

// FreeRADIUSClient fetches metrics from status server.
type FreeRADIUSClient struct {
	mainAddr string
	packets  []packetWrapper
	timeout  time.Duration
	metrics  map[string]*prometheus.Desc
}

type packetWrapper struct {
	address string
	packet  *radius.Packet
}

func newPacket(secret []byte, address string, statAttr radius.Attribute) (*radius.Packet, error) {
	auth := make([]byte, 16)
	hash := hmac.New(md5.New, secret)
	packet := radius.New(radius.CodeStatusServer, secret)

	rfc2869.MessageAuthenticator_Set(packet, auth)
	freeradius.SetValue(packet, freeradius.StatisticsType, statAttr)

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		log.Fatalf("failed parsing home server ip ('%v'): %v\n", address, err)
	}
	portStr = strings.TrimPrefix(portStr, ":")

	ip := net.ParseIP(host)
	if ip == nil {
		log.Fatalln("ip is nil")
	}

	attrIP, err := radius.NewIPAddr(ip)
	if err != nil {
		log.Fatalln(err)
	}

	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		log.Fatalf("failed parsing port ('%v') to uint: %v\n", port, err)
	}

	freeradius.SetValue(packet, freeradius.ServerIPAddress, attrIP)
	freeradius.SetValue(packet, freeradius.ServerPort, radius.NewInteger(uint32(port)))

	encode, err := packet.Encode()
	if err != nil {
		return nil, err
	}

	hash.Write(encode)
	rfc2869.MessageAuthenticator_Set(packet, hash.Sum(nil))

	return packet, err
}

// NewFreeRADIUSClient creates an FreeRADIUSClient.
func NewFreeRADIUSClient(addr string, homeServers []string, secret string, timeout int) (*FreeRADIUSClient, error) {
	client := &FreeRADIUSClient{}
	client.mainAddr = addr
	client.timeout = time.Duration(timeout) * time.Millisecond
	client.metrics = metrics
	packet, err := newPacket([]byte(secret), addr, radius.NewInteger(uint32(freeradius.StatisticsTypeAll)))
	if err != nil {
		log.Fatalf("failed creating new packet for address '%v'\n", addr)
	}
	client.packets = append(client.packets, packetWrapper{packet: packet, address: addr})

	// add home server stats
	for _, hs := range homeServers {
		if hs == "" {
			continue
		}
		packet, err := newPacket([]byte(secret), hs, radius.NewInteger(uint32(
			freeradius.StatisticsTypeAuthentication| // will give "Home server is not auth" stats error when server is acct (but won't fail and give the available metrics)
				freeradius.StatisticsTypeAccounting| // will give "Home server is not acct" stats error when server is auth (but won't fail and give the available metrics)
				freeradius.StatisticsTypeInternal|
				freeradius.StatisticsTypeHomeServer,
		)))
		if err != nil {
			log.Fatalf("failed creating new packet for address '%v'\n", addr)
		}
		client.packets = append(client.packets, packetWrapper{packet: packet, address: hs})
	}

	return client, nil
}

// Stats fetches statistics.
func (f *FreeRADIUSClient) Stats() ([]prometheus.Metric, error) {
	var allStats []prometheus.Metric

	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()

	for _, p := range f.packets {
		stats := Statistics{}

		response, err := radius.Exchange(ctx, p.packet, f.mainAddr)
		if err != nil {
			return nil, fmt.Errorf("exchange failed: %w", err)

		}

		if response.Code != radius.CodeAccessAccept {
			return nil, fmt.Errorf("got response code '%v'", response.Code)
		}

		statsErr, err := freeradius.GetString(response, freeradius.StatsError)
		if err == nil { // when there is no lookup error for this attribute, there is a freeradius-stats-error
			log.Printf("error form stats server (main %v or home server: %v): '%v'", f.mainAddr, p.address, statsErr)
		}

		stats.Error = statsErr
		m := prometheus.MustNewConstMetric(f.metrics["freeradius_stats_error"], prometheus.GaugeValue, 1, stats.Error, p.address)
		allStats = append(allStats, m)

		if stats.Server.LastPacketRecv, err = freeradius.GetDate(response, freeradius.LastPacketRecv); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_last_packet_recv"], prometheus.GaugeValue, float64(stats.Server.LastPacketRecv.Unix()), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}
		if stats.Server.LastPacketSent, err = freeradius.GetDate(response, freeradius.LastPacketSent); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_last_packet_sent"], prometheus.GaugeValue, float64(stats.Server.LastPacketSent.Unix()), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.HUPTime, err = freeradius.GetDate(response, freeradius.HUPTime); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_hup_time"], prometheus.GaugeValue, float64(stats.Server.HUPTime.Unix()), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}
		if stats.Server.StartTime, err = freeradius.GetDate(response, freeradius.StartTime); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_start_time"], prometheus.GaugeValue, float64(stats.Server.StartTime.Unix()), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.State, err = freeradius.GetInt(response, freeradius.ServerState); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_state"], prometheus.GaugeValue, float64(stats.Server.State), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.TimeOfDeath, err = freeradius.GetDate(response, freeradius.ServerTimeOfDeath); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_time_of_death"], prometheus.GaugeValue, float64(stats.Server.TimeOfDeath.Unix()), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}
		if stats.Server.TimeOfLife, err = freeradius.GetDate(response, freeradius.ServerTimeOfLife); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_time_of_life"], prometheus.GaugeValue, float64(stats.Server.TimeOfLife.Unix()), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.EmaWindow, err = freeradius.GetInt(response, freeradius.EmaWindow); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_ema_window"], prometheus.GaugeValue, float64(stats.Server.EmaWindow), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.EmaUsecWindow1, err = freeradius.GetInt(response, freeradius.EmaUsecWindow1); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_ema_window1_usec"], prometheus.GaugeValue, float64(stats.Server.EmaUsecWindow1), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.EmaUsecWindow10, err = freeradius.GetInt(response, freeradius.EmaUsecWindow10); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_ema_window10_usec"], prometheus.GaugeValue, float64(stats.Server.EmaUsecWindow10), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.OutstandingRequests, err = freeradius.GetInt(response, freeradius.ServerOutstandingRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_outstanding_requests"], prometheus.GaugeValue, float64(stats.Server.OutstandingRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.QueuePPSIn, err = freeradius.GetInt(response, freeradius.QueuePPSIn); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_pps_in"], prometheus.GaugeValue, float64(stats.Server.QueuePPSIn), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.QueuePPSOut, err = freeradius.GetInt(response, freeradius.QueuePPSOut); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_pps_out"], prometheus.GaugeValue, float64(stats.Server.QueuePPSOut), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Server.QueueUsePercentage, err = freeradius.GetInt(response, freeradius.QueueUsePercentage); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_use_percentage"], prometheus.GaugeValue, float64(stats.Server.QueuePPSOut), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Access.Requests, err = freeradius.GetInt(response, freeradius.TotalAccessRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_access_requests"], prometheus.CounterValue, float64(stats.Access.Requests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Access.Accepts, err = freeradius.GetInt(response, freeradius.TotalAccessAccepts); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_access_accepts"], prometheus.CounterValue, float64(stats.Access.Accepts), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Access.Rejects, err = freeradius.GetInt(response, freeradius.TotalAccessRejects); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_access_rejects"], prometheus.CounterValue, float64(stats.Access.Rejects), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Access.Challenges, err = freeradius.GetInt(response, freeradius.TotalAccessChallenges); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_access_challenges"], prometheus.CounterValue, float64(stats.Access.Challenges), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Auth.Responses, err = freeradius.GetInt(response, freeradius.TotalAuthResponses); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_responses"], prometheus.CounterValue, float64(stats.Auth.Responses), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Auth.DuplicateRequests, err = freeradius.GetInt(response, freeradius.TotalAuthDuplicateRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_duplicate_requests"], prometheus.CounterValue, float64(stats.Auth.DuplicateRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Auth.MalformedRequests, err = freeradius.GetInt(response, freeradius.TotalAuthMalformedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_malformed_requests"], prometheus.CounterValue, float64(stats.Auth.MalformedRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Auth.InvalidRequests, err = freeradius.GetInt(response, freeradius.TotalAuthInvalidRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_invalid_requests"], prometheus.CounterValue, float64(stats.Auth.InvalidRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Auth.DroppedRequests, err = freeradius.GetInt(response, freeradius.TotalAuthDroppedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_dropped_requests"], prometheus.CounterValue, float64(stats.Auth.DroppedRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Auth.UnknownTypes, err = freeradius.GetInt(response, freeradius.TotalAuthUnknownTypes); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_auth_unknown_types"], prometheus.CounterValue, float64(stats.Auth.UnknownTypes), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccess.Requests, err = freeradius.GetInt(response, freeradius.TotalProxyAccessRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_access_requests"], prometheus.CounterValue, float64(stats.ProxyAccess.Requests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccess.Accepts, err = freeradius.GetInt(response, freeradius.TotalProxyAccessAccepts); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_access_accepts"], prometheus.CounterValue, float64(stats.ProxyAccess.Accepts), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccess.Rejects, err = freeradius.GetInt(response, freeradius.TotalProxyAccessRejects); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_access_rejects"], prometheus.CounterValue, float64(stats.ProxyAccess.Rejects), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccess.Challenges, err = freeradius.GetInt(response, freeradius.TotalProxyAccessChallenges); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_access_challenges"], prometheus.CounterValue, float64(stats.ProxyAccess.Challenges), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAuth.Responses, err = freeradius.GetInt(response, freeradius.TotalProxyAuthResponses); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_responses"], prometheus.CounterValue, float64(stats.ProxyAuth.Responses), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAuth.DuplicateRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAuthDuplicateRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_duplicate_requests"], prometheus.CounterValue, float64(stats.ProxyAuth.DuplicateRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAuth.MalformedRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAuthMalformedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_malformed_requests"], prometheus.CounterValue, float64(stats.ProxyAuth.MalformedRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAuth.InvalidRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAuthInvalidRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_invalid_requests"], prometheus.CounterValue, float64(stats.ProxyAuth.InvalidRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAuth.DroppedRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAuthDroppedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_dropped_requests"], prometheus.CounterValue, float64(stats.ProxyAuth.DroppedRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAuth.UnknownTypes, err = freeradius.GetInt(response, freeradius.TotalProxyAuthUnknownTypes); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_auth_unknown_types"], prometheus.CounterValue, float64(stats.ProxyAuth.UnknownTypes), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Accounting.Requests, err = freeradius.GetInt(response, freeradius.TotalAccountingRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_requests"], prometheus.CounterValue, float64(stats.Accounting.Requests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Accounting.Responses, err = freeradius.GetInt(response, freeradius.TotalAccountingResponses); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_responses"], prometheus.CounterValue, float64(stats.Accounting.Responses), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Accounting.DuplicateRequests, err = freeradius.GetInt(response, freeradius.TotalAcctDuplicateRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_duplicate_requests"], prometheus.CounterValue, float64(stats.Accounting.DuplicateRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Accounting.MalformedRequests, err = freeradius.GetInt(response, freeradius.TotalAcctMalformedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_malformed_requests"], prometheus.CounterValue, float64(stats.Accounting.MalformedRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Accounting.InvalidRequests, err = freeradius.GetInt(response, freeradius.TotalAcctInvalidRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_invalid_requests"], prometheus.CounterValue, float64(stats.Accounting.InvalidRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Accounting.DroppedRequests, err = freeradius.GetInt(response, freeradius.TotalAcctDroppedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_dropped_requests"], prometheus.CounterValue, float64(stats.Accounting.DroppedRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Accounting.UnknownTypes, err = freeradius.GetInt(response, freeradius.TotalAcctUnknownTypes); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_acct_unknown_types"], prometheus.CounterValue, float64(stats.Accounting.UnknownTypes), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccounting.Requests, err = freeradius.GetInt(response, freeradius.TotalProxyAccountingRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_requests"], prometheus.CounterValue, float64(stats.ProxyAccounting.Requests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccounting.Responses, err = freeradius.GetInt(response, freeradius.TotalProxyAccountingResponses); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_responses"], prometheus.CounterValue, float64(stats.ProxyAccounting.Responses), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccounting.DuplicateRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAcctDuplicateRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_duplicate_requests"], prometheus.CounterValue, float64(stats.ProxyAccounting.DuplicateRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccounting.MalformedRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAcctMalformedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_malformed_requests"], prometheus.CounterValue, float64(stats.ProxyAccounting.MalformedRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccounting.InvalidRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAcctInvalidRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_invalid_requests"], prometheus.CounterValue, float64(stats.ProxyAccounting.InvalidRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccounting.DroppedRequests, err = freeradius.GetInt(response, freeradius.TotalProxyAcctDroppedRequests); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_dropped_requests"], prometheus.CounterValue, float64(stats.ProxyAccounting.DroppedRequests), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.ProxyAccounting.UnknownTypes, err = freeradius.GetInt(response, freeradius.TotalProxyAcctUnknownTypes); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_total_proxy_acct_unknown_types"], prometheus.CounterValue, float64(stats.ProxyAccounting.UnknownTypes), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Internal.QueueLenInternal, err = freeradius.GetInt(response, freeradius.QueueLenInternal); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_len_internal"], prometheus.GaugeValue, float64(stats.Internal.QueueLenInternal), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Internal.QueueLenProxy, err = freeradius.GetInt(response, freeradius.QueueLenProxy); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_len_proxy"], prometheus.GaugeValue, float64(stats.Internal.QueueLenProxy), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Internal.QueueLenAuth, err = freeradius.GetInt(response, freeradius.QueueLenAuth); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_len_auth"], prometheus.GaugeValue, float64(stats.Internal.QueueLenAuth), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Internal.QueueLenAcct, err = freeradius.GetInt(response, freeradius.QueueLenAcct); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_len_acct"], prometheus.GaugeValue, float64(stats.Internal.QueueLenAcct), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}

		if stats.Internal.QueueLenDetail, err = freeradius.GetInt(response, freeradius.QueueLenDetail); err == nil {
			allStats = append(allStats, prometheus.MustNewConstMetric(f.metrics["freeradius_queue_len_detail"], prometheus.GaugeValue, float64(stats.Internal.QueueLenDetail), p.address))
		} else if err != nil && err != radius.ErrNoAttribute {
			log.Println(err)
		}
	}

	return allStats, nil
}

var metrics = map[string]*prometheus.Desc{
	"freeradius_total_access_requests":               prometheus.NewDesc("freeradius_total_access_requests", "Total access requests", []string{"address"}, nil),
	"freeradius_total_access_accepts":                prometheus.NewDesc("freeradius_total_access_accepts", "Total access accepts", []string{"address"}, nil),
	"freeradius_total_access_rejects":                prometheus.NewDesc("freeradius_total_access_rejects", "Total access rejects", []string{"address"}, nil),
	"freeradius_total_access_challenges":             prometheus.NewDesc("freeradius_total_access_challenges", "Total access challenges", []string{"address"}, nil),
	"freeradius_total_auth_responses":                prometheus.NewDesc("freeradius_total_auth_responses", "Total auth responses", []string{"address"}, nil),
	"freeradius_total_auth_duplicate_requests":       prometheus.NewDesc("freeradius_total_auth_duplicate_requests", "Total auth duplicate requests", []string{"address"}, nil),
	"freeradius_total_auth_malformed_requests":       prometheus.NewDesc("freeradius_total_auth_malformed_requests", "Total auth malformed requests", []string{"address"}, nil),
	"freeradius_total_auth_invalid_requests":         prometheus.NewDesc("freeradius_total_auth_invalid_requests", "Total auth invalid requests", []string{"address"}, nil),
	"freeradius_total_auth_dropped_requests":         prometheus.NewDesc("freeradius_total_auth_dropped_requests", "Total auth dropped requests", []string{"address"}, nil),
	"freeradius_total_auth_unknown_types":            prometheus.NewDesc("freeradius_total_auth_unknown_types", "Total auth unknown types", []string{"address"}, nil),
	"freeradius_total_proxy_access_requests":         prometheus.NewDesc("freeradius_total_proxy_access_requests", "Total proxy access requests", []string{"address"}, nil),
	"freeradius_total_proxy_access_accepts":          prometheus.NewDesc("freeradius_total_proxy_access_accepts", "Total proxy access accepts", []string{"address"}, nil),
	"freeradius_total_proxy_access_rejects":          prometheus.NewDesc("freeradius_total_proxy_access_rejects", "Total proxy access rejects", []string{"address"}, nil),
	"freeradius_total_proxy_access_challenges":       prometheus.NewDesc("freeradius_total_proxy_access_challenges", "Total proxy access challenges", []string{"address"}, nil),
	"freeradius_total_proxy_auth_responses":          prometheus.NewDesc("freeradius_total_proxy_auth_responses", "Total proxy auth responses", []string{"address"}, nil),
	"freeradius_total_proxy_auth_duplicate_requests": prometheus.NewDesc("freeradius_total_proxy_auth_duplicate_requests", "Total proxy auth duplicate requests", []string{"address"}, nil),
	"freeradius_total_proxy_auth_malformed_requests": prometheus.NewDesc("freeradius_total_proxy_auth_malformed_requests", "Total proxy auth malformed requests", []string{"address"}, nil),
	"freeradius_total_proxy_auth_invalid_requests":   prometheus.NewDesc("freeradius_total_proxy_auth_invalid_requests", "Total proxy auth invalid requests", []string{"address"}, nil),
	"freeradius_total_proxy_auth_dropped_requests":   prometheus.NewDesc("freeradius_total_proxy_auth_dropped_requests", "Total proxy auth dropped requests", []string{"address"}, nil),
	"freeradius_total_proxy_auth_unknown_types":      prometheus.NewDesc("freeradius_total_proxy_auth_unknown_types", "Total proxy auth unknown types", []string{"address"}, nil),
	"freeradius_total_acct_requests":                 prometheus.NewDesc("freeradius_total_acct_requests", "Total acct requests", []string{"address"}, nil),
	"freeradius_total_acct_responses":                prometheus.NewDesc("freeradius_total_acct_responses", "Total acct responses", []string{"address"}, nil),
	"freeradius_total_acct_duplicate_requests":       prometheus.NewDesc("freeradius_total_acct_duplicate_requests", "Total acct duplicate requests", []string{"address"}, nil),
	"freeradius_total_acct_malformed_requests":       prometheus.NewDesc("freeradius_total_acct_malformed_requests", "Total acct malformed requests", []string{"address"}, nil),
	"freeradius_total_acct_invalid_requests":         prometheus.NewDesc("freeradius_total_acct_invalid_requests", "Total acct invalid requests", []string{"address"}, nil),
	"freeradius_total_acct_dropped_requests":         prometheus.NewDesc("freeradius_total_acct_dropped_requests", "Total acct dropped requests", []string{"address"}, nil),
	"freeradius_total_acct_unknown_types":            prometheus.NewDesc("freeradius_total_acct_unknown_types", "Total acct unknown types", []string{"address"}, nil),
	"freeradius_total_proxy_acct_requests":           prometheus.NewDesc("freeradius_total_proxy_acct_requests", "Total proxy acct requests", []string{"address"}, nil),
	"freeradius_total_proxy_acct_responses":          prometheus.NewDesc("freeradius_total_proxy_acct_responses", "Total proxy acct responses", []string{"address"}, nil),
	"freeradius_total_proxy_acct_duplicate_requests": prometheus.NewDesc("freeradius_total_proxy_acct_duplicate_requests", "Total proxy acct duplicate requests", []string{"address"}, nil),
	"freeradius_total_proxy_acct_malformed_requests": prometheus.NewDesc("freeradius_total_proxy_acct_malformed_requests", "Total proxy acct malformed requests", []string{"address"}, nil),
	"freeradius_total_proxy_acct_invalid_requests":   prometheus.NewDesc("freeradius_total_proxy_acct_invalid_requests", "Total proxy acct invalid requests", []string{"address"}, nil),
	"freeradius_total_proxy_acct_dropped_requests":   prometheus.NewDesc("freeradius_total_proxy_acct_dropped_requests", "Total proxy acct dropped requests", []string{"address"}, nil),
	"freeradius_total_proxy_acct_unknown_types":      prometheus.NewDesc("freeradius_total_proxy_acct_unknown_types", "Total proxy acct unknown types", []string{"address"}, nil),
	"freeradius_queue_len_internal":                  prometheus.NewDesc("freeradius_queue_len_internal", "Interal queue length", []string{"address"}, nil),
	"freeradius_queue_len_proxy":                     prometheus.NewDesc("freeradius_queue_len_proxy", "Proxy queue length", []string{"address"}, nil),
	"freeradius_queue_len_auth":                      prometheus.NewDesc("freeradius_queue_len_auth", "Auth queue length", []string{"address"}, nil),
	"freeradius_queue_len_acct":                      prometheus.NewDesc("freeradius_queue_len_acct", "Acct queue length", []string{"address"}, nil),
	"freeradius_queue_len_detail":                    prometheus.NewDesc("freeradius_queue_len_detail", "Detail queue length", []string{"address"}, nil),
	"freeradius_last_packet_recv":                    prometheus.NewDesc("freeradius_last_packet_recv", "Epoch timestamp when the last packet was received", []string{"address"}, nil),
	"freeradius_last_packet_sent":                    prometheus.NewDesc("freeradius_last_packet_sent", "Epoch timestamp when the last packet was sent", []string{"address"}, nil),
	"freeradius_start_time":                          prometheus.NewDesc("freeradius_start_time", "Epoch timestamp when the server was started", []string{"address"}, nil),
	"freeradius_hup_time":                            prometheus.NewDesc("freeradius_hup_time", "Epoch timestamp when the server hang up (If start == hup, it hasn't been hup'd yet)", []string{"address"}, nil),
	"freeradius_state":                               prometheus.NewDesc("freeradius_state", "State of the server. Alive = 0; Zombie = 1; Dead = 2; Idle = 3", []string{"address"}, nil),
	"freeradius_time_of_death":                       prometheus.NewDesc("freeradius_time_of_death", "Epoch timestamp when a home server is marked as 'dead'", []string{"address"}, nil),
	"freeradius_time_of_life":                        prometheus.NewDesc("freeradius_time_of_life", "Epoch timestamp when a home server is marked as 'alive'", []string{"address"}, nil),
	"freeradius_ema_window":                          prometheus.NewDesc("freeradius_ema_window", "Exponential moving average of home server response time", []string{"address"}, nil),
	"freeradius_ema_window1_usec":                    prometheus.NewDesc("freeradius_ema_window1_usec", "Window-1 is the average is calculated over 'window' packets", []string{"address"}, nil),
	"freeradius_ema_window10_usec":                   prometheus.NewDesc("freeradius_ema_window10_usec", "Window-10 is the average is calculated over '10 * window' packets", []string{"address"}, nil),
	"freeradius_outstanding_requests":                prometheus.NewDesc("freeradius_outstanding_requests", "Outstanding requests", []string{"address"}, nil),
	"freeradius_queue_pps_in":                        prometheus.NewDesc("freeradius_queue_pps_in", "Queue PPS in", []string{"address"}, nil),
	"freeradius_queue_pps_out":                       prometheus.NewDesc("freeradius_queue_pps_out", "Queue PPS out", []string{"address"}, nil),
	"freeradius_queue_use_percentage":                prometheus.NewDesc("freeradius_queue_use_percentage", "Queue usage percentage", []string{"address"}, nil),
	"freeradius_stats_error":                         prometheus.NewDesc("freeradius_stats_error", "Stats error as label with a const value of 1", []string{"error", "address"}, nil),
}
