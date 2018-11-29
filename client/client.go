package client

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2869"

	"github.com/bvantagelimited/freeradius_exporter/freeradius"
)

// Statistics type.
type Statistics struct {
	Access          Access
	Auth            Auth
	ProxyAccess     Access
	ProxyAuth       Auth
	Accounting      Accounting
	ProxyAccounting Accounting
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

// FreeRADIUSClient fetches metrics from status server.
type FreeRADIUSClient struct {
	addr    string
	packet  *radius.Packet
	timeout time.Duration
}

// NewFreeRADIUSClient creates an FreeRADIUSClient.
func NewFreeRADIUSClient(addr, secret string, timeout int) (*FreeRADIUSClient, error) {
	client := &FreeRADIUSClient{}

	auth := make([]byte, 16)
	hash := hmac.New(md5.New, []byte(secret))
	packet := radius.New(radius.CodeStatusServer, []byte(secret))

	rfc2869.MessageAuthenticator_Set(packet, auth)
	freeradius.SetValue(packet, freeradius.StatisticsType, radius.NewInteger(uint32(freeradius.StatisticsTypeAuthAcctProxyAuthAcct)))

	encode, err := packet.Encode()
	if err != nil {
		return nil, err
	}

	hash.Write(encode)
	rfc2869.MessageAuthenticator_Set(packet, hash.Sum(nil))

	client.addr = addr
	client.packet = packet
	client.timeout = time.Duration(timeout) * time.Millisecond

	return client, nil
}

// Stats fetches statistics.
func (f *FreeRADIUSClient) Stats() (Statistics, error) {
	stats := Statistics{}

	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()

	response, err := radius.Exchange(ctx, f.packet, f.addr)
	if err != nil {
		return stats, err
	}

	if response.Code == radius.CodeAccessAccept {
		stats.Access.Requests, err = freeradius.GetValue(response, freeradius.TotalAccessRequests)
		if err != nil {
			return stats, err
		}
		stats.Access.Accepts, err = freeradius.GetValue(response, freeradius.TotalAccessAccepts)
		if err != nil {
			return stats, err
		}
		stats.Access.Rejects, err = freeradius.GetValue(response, freeradius.TotalAccessRejects)
		if err != nil {
			return stats, err
		}
		stats.Access.Challenges, err = freeradius.GetValue(response, freeradius.TotalAccessChallenges)
		if err != nil {
			return stats, err
		}
		stats.Auth.Responses, err = freeradius.GetValue(response, freeradius.TotalAuthResponses)
		if err != nil {
			return stats, err
		}
		stats.Auth.DuplicateRequests, err = freeradius.GetValue(response, freeradius.TotalAuthDuplicateRequests)
		if err != nil {
			return stats, err
		}
		stats.Auth.MalformedRequests, err = freeradius.GetValue(response, freeradius.TotalAuthMalformedRequests)
		if err != nil {
			return stats, err
		}
		stats.Auth.InvalidRequests, err = freeradius.GetValue(response, freeradius.TotalAuthInvalidRequests)
		if err != nil {
			return stats, err
		}
		stats.Auth.DroppedRequests, err = freeradius.GetValue(response, freeradius.TotalAuthDroppedRequests)
		if err != nil {
			return stats, err
		}
		stats.Auth.UnknownTypes, err = freeradius.GetValue(response, freeradius.TotalAuthUnknownTypes)
		if err != nil {
			return stats, err
		}
		stats.ProxyAccess.Requests, err = freeradius.GetValue(response, freeradius.TotalProxyAccessRequests)
		if err != nil {
			return stats, err
		}
		stats.ProxyAccess.Accepts, err = freeradius.GetValue(response, freeradius.TotalProxyAccessAccepts)
		if err != nil {
			return stats, err
		}
		stats.ProxyAccess.Rejects, err = freeradius.GetValue(response, freeradius.TotalProxyAccessRejects)
		if err != nil {
			return stats, err
		}
		stats.ProxyAccess.Challenges, err = freeradius.GetValue(response, freeradius.TotalProxyAccessChallenges)
		if err != nil {
			return stats, err
		}
		stats.ProxyAuth.Responses, err = freeradius.GetValue(response, freeradius.TotalProxyAuthResponses)
		if err != nil {
			return stats, err
		}
		stats.ProxyAuth.DuplicateRequests, err = freeradius.GetValue(response, freeradius.TotalProxyAuthDuplicateRequests)
		if err != nil {
			return stats, err
		}
		stats.ProxyAuth.MalformedRequests, err = freeradius.GetValue(response, freeradius.TotalProxyAuthMalformedRequests)
		if err != nil {
			return stats, err
		}
		stats.ProxyAuth.InvalidRequests, err = freeradius.GetValue(response, freeradius.TotalProxyAuthInvalidRequests)
		if err != nil {
			return stats, err
		}
		stats.ProxyAuth.DroppedRequests, err = freeradius.GetValue(response, freeradius.TotalProxyAuthDroppedRequests)
		if err != nil {
			return stats, err
		}
		stats.ProxyAuth.UnknownTypes, err = freeradius.GetValue(response, freeradius.TotalProxyAuthUnknownTypes)
		if err != nil {
			return stats, err
		}
		stats.Accounting.Requests, err = freeradius.GetValue(response, freeradius.TotalAccountingRequests)
		if err != nil {
			return stats, err
		}
		stats.Accounting.Responses, err = freeradius.GetValue(response, freeradius.TotalAccountingResponses)
		if err != nil {
			return stats, err
		}
		stats.Accounting.DuplicateRequests, err = freeradius.GetValue(response, freeradius.TotalAcctDuplicateRequests)
		if err != nil {
			return stats, err
		}
		stats.Accounting.MalformedRequests, err = freeradius.GetValue(response, freeradius.TotalAcctMalformedRequests)
		if err != nil {
			return stats, err
		}
		stats.Accounting.InvalidRequests, err = freeradius.GetValue(response, freeradius.TotalAcctInvalidRequests)
		if err != nil {
			return stats, err
		}
		stats.Accounting.DroppedRequests, err = freeradius.GetValue(response, freeradius.TotalAcctDroppedRequests)
		if err != nil {
			return stats, err
		}
		stats.Accounting.UnknownTypes, err = freeradius.GetValue(response, freeradius.TotalAcctUnknownTypes)
		if err != nil {
			return stats, err
		}
		stats.ProxyAccounting.Requests, err = freeradius.GetValue(response, freeradius.TotalProxyAccountingRequests)
		if err != nil {
			return stats, err
		}
		stats.ProxyAccounting.Responses, err = freeradius.GetValue(response, freeradius.TotalProxyAccountingResponses)
		if err != nil {
			return stats, err
		}
		stats.ProxyAccounting.DuplicateRequests, err = freeradius.GetValue(response, freeradius.TotalProxyAcctDuplicateRequests)
		if err != nil {
			return stats, err
		}
		stats.ProxyAccounting.MalformedRequests, err = freeradius.GetValue(response, freeradius.TotalProxyAcctMalformedRequests)
		if err != nil {
			return stats, err
		}
		stats.ProxyAccounting.InvalidRequests, err = freeradius.GetValue(response, freeradius.TotalProxyAcctInvalidRequests)
		if err != nil {
			return stats, err
		}
		stats.ProxyAccounting.DroppedRequests, err = freeradius.GetValue(response, freeradius.TotalProxyAcctDroppedRequests)
		if err != nil {
			return stats, err
		}
		stats.ProxyAccounting.UnknownTypes, err = freeradius.GetValue(response, freeradius.TotalProxyAcctUnknownTypes)
		if err != nil {
			return stats, err
		}
	}

	return stats, nil
}
