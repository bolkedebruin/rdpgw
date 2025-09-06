package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/andrewheberle/rdpsign"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/config/hostselection"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/rdp"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/spf13/afero"
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
		HostSelection: hostselection.RoundRobin,
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
	c.HostSelection = hostselection.Unsigned
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
	c.HostSelection = hostselection.Any
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
	c.HostSelection = hostselection.Signed
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
		HostSelection:     hostselection.RoundRobin,
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

func TestHandler_HandleSignedDownload(t *testing.T) {
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
		HostSelection:     hostselection.RoundRobin,
		Hosts:             hosts,
		PAATokenGenerator: paaTokenMock,
		GatewayAddress:    u,
		RdpOpts:           RdpOpts{SplitUserDomain: true},
	}
	h := c.NewHandler()

	// set up rdp signer
	fs := afero.NewMemMapFs()
	if err := genKeypair(fs); err != nil {
		t.Errorf("could not generate key pair for testing: %s", err)
	}
	signer, err := rdpsign.New("test.crt", "test.key", rdpsign.WithFs(fs))
	if err != nil {
		t.Errorf("could not create *rdpsign.Signer for testing: %s", err)
	}
	h.rdpSigner = signer

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

	signscopeWant := "GatewayHostname,Full Address,GatewayCredentialsSource,GatewayProfileUsageMethod,GatewayUsageMethod,Alternate Full Address"
	if data["signscope"] != signscopeWant {
		t.Errorf("signscope key in rdp does not match: got %v want %v", data["signscope"], signscopeWant)
	}

	if _, found := data["signature"]; !found {
		t.Errorf("no signature found in rdp")
	}

}

func TestHandler_HandleDownloadWithRdpTemplate(t *testing.T) {
	f, err := os.CreateTemp("", "rdp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	err = os.WriteFile(f.Name(), []byte("domain:s:testdomain\r\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("GET", "/connect", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	id := identity.NewUser()

	id.SetUserName(testuser)
	id.SetAuthenticated(true)

	req = identity.AddToRequestCtx(id, req)

	u, _ := url.Parse(gateway)
	c := Config{
		HostSelection:     hostselection.RoundRobin,
		Hosts:             hosts,
		PAATokenGenerator: paaTokenMock,
		GatewayAddress:    u,
		RdpOpts:           RdpOpts{SplitUserDomain: true},
		TemplateFile:      f.Name(),
	}
	h := c.NewHandler()

	hh := http.HandlerFunc(h.HandleDownload)
	hh.ServeHTTP(rr, req)

	data := rdpToMap(strings.Split(rr.Body.String(), rdp.CRLF))
	if data["domain"] != "testdomain" {
		t.Errorf("domain key in rdp does not match: got %v want %v", data["domain"], "testdomain")
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

func genKeypair(fs afero.Fs) error {
	// generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// convert to DER
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	// encode DER private key as PEM
	if err := func() error {
		f, err := fs.Create("test.key")
		if err != nil {
			return err
		}
		defer f.Close()

		return pem.Encode(f, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		})
	}(); err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Example Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Minute * 10),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	// encode cert as PEM
	if err := func() error {
		f, err := fs.Create("test.crt")
		if err != nil {
			return err
		}
		defer f.Close()

		return pem.Encode(f, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		})
	}(); err != nil {
		return err
	}

	return nil
}
