package web

import (
	"context"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/rdp"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	testuser = "test_user"
	gateway  = "https://my.gateway.com:993"
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
	h := c.NewHandler()

	u := &url.URL{
		Host: "example.com",
	}
	vals := u.Query()

	host, err := h.getHost(ctx, u)
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
	h = c.NewHandler()
	host, err = h.getHost(ctx, u)
	if err == nil {
		t.Fatalf("Accepted host %s is not in hosts list", host)
	}

	vals.Set("host", hosts[0])
	u.RawQuery = vals.Encode()
	h = c.NewHandler()
	host, err = h.getHost(ctx, u)
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
	h = c.NewHandler()
	host, err = h.getHost(ctx, u)
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
	h = c.NewHandler()
	host, err = h.getHost(ctx, u)
	if err != nil {
		t.Fatalf("Not accepted host %s is in hosts list (err: %s)", hosts[0], err)
	}
	if host != hosts[0] {
		t.Fatalf("%s does not equal %s", host, hosts[0])
	}
}

func TestHandler_HandleDownload(t *testing.T) {
	req, err := http.NewRequest("GET", "/connect", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	id := identity.NewUser()

	id.SetUserName(testuser)
	id.SetAuthenticated(true)

	req = identity.AddToRequestCtx(id, req)
	ctx := req.Context()

	u, _ := url.Parse(gateway)
	c := Config{
		HostSelection:     "roundrobin",
		Hosts:             hosts,
		PAATokenGenerator: paaTokenMock,
		GatewayAddress:    u,
		RdpOpts:           RdpOpts{SplitUserDomain: true},
	}
	h := c.NewHandler()

	hh := http.HandlerFunc(h.HandleDownload)
	hh.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	if ctype := rr.Header().Get("Content-Type"); ctype != "application/x-rdp" {
		t.Errorf("content type header does not match: got %v want %v",
			ctype, "application/json")
	}

	if cdisp := rr.Header().Get("Content-Disposition"); cdisp == "" {
		t.Errorf("content disposition is nil")
	}

	data := rdpToMap(strings.Split(rr.Body.String(), rdp.CRLF))
	if data["username"] != testuser {
		t.Errorf("username key in rdp does not match: got %v want %v", data["username"], testuser)
	}

	if data["gatewayhostname"] != u.Host {
		t.Errorf("gatewayhostname key in rdp does not match: got %v want %v", data["gatewayhostname"], u.Host)
	}

	if token, _ := paaTokenMock(ctx, testuser, data["full address"]); token != data["gatewayaccesstoken"] {
		t.Errorf("gatewayaccesstoken key in rdp does not match username_full address: got %v want %v",
			data["gatewayaccesstoken"], token)
	}

	if !contains(data["full address"], hosts) {
		t.Errorf("full address key in rdp is not in allowed hosts list: go %v want in %v",
			data["full address"], hosts)
	}

}

func paaTokenMock(ctx context.Context, username string, host string) (string, error) {
	return username + "_" + host, nil
}

func rdpToMap(rdp []string) map[string]string {
	ret := make(map[string]string)

	for s := range rdp {
		d := strings.SplitN(rdp[s], ":", 3)
		if len(d) >= 2 {
			ret[d[0]] = d[2]
		}
	}

	return ret
}
