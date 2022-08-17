package api

import (
	"context"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"net/url"
	"testing"
)

var (
	hosts = []string{"10.0.0.1:3389", "10.1.1.1:3000", "32.32.11.1", "remote.host.com"}
	key   = []byte("thisisasessionkeyreplacethisjetzt")
)

func contains(needle string, haystack []string) bool {
	for _, val := range haystack {
		if val == needle {
			return true
		}
	}
	return false
}

func TestGetHost(t *testing.T) {
	ctx := context.Background()
	c := Config{
		HostSelection: "roundrobin",
		Hosts:         hosts,
	}
	u := &url.URL{
		Host: "example.com",
	}
	vals := u.Query()

	host, err := c.getHost(ctx, u)
	if err != nil {
		t.Fatalf("#{err}")
	}
	if !contains(host, hosts) {
		t.Fatalf("host %s is not in hosts list", host)
	}

	// check unsigned
	c.HostSelection = "unsigned"
	vals.Set("host", "in.valid.host")
	u.RawQuery = vals.Encode()
	host, err = c.getHost(ctx, u)
	if err == nil {
		t.Fatalf("Accepted host %s is not in hosts list", host)
	}

	vals.Set("host", hosts[0])
	u.RawQuery = vals.Encode()
	host, err = c.getHost(ctx, u)
	if err != nil {
		t.Fatalf("Not accepted host %s is in hosts list (err: %s)", hosts[0], err)
	}
	if host != hosts[0] {
		t.Fatalf("host %s is not equal to input %s", host, hosts[0])
	}

	// check any
	c.HostSelection = "any"
	test := "bla.bla.com"
	vals.Set("host", test)
	u.RawQuery = vals.Encode()
	host, err = c.getHost(ctx, u)
	if err != nil {
		t.Fatalf("%s is not accepted", host)
	}
	if test != host {
		t.Fatalf("Returned host %s is not equal to input host %s", host, test)
	}

	// check signed
	c.HostSelection = "signed"
	c.QueryInfo = security.QueryInfo
	issuer := "rdpgwtest"
	security.QuerySigningKey = key
	queryToken, err := security.GenerateQueryToken(ctx, hosts[0], issuer)
	if err != nil {
		t.Fatalf("cannot generate token")
	}
	vals.Set("host", queryToken)
	u.RawQuery = vals.Encode()
	host, err = c.getHost(ctx, u)
	if err != nil {
		t.Fatalf("Not accepted host %s is in hosts list (err: %s)", hosts[0], err)
	}
	if host != hosts[0] {
		t.Fatalf("%s does not equal %s", host, hosts[0])
	}
}
