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

	// check any -- TEST-NET-3 literal stays in the policy's "publicly
	// routable" branch so this case still exercises the happy path.
	c.HostSelection = "any"
	test := "203.0.113.5:3389"
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

// TestGetHostAnyRejectsSensitiveDestinations asserts that with
// HostSelection="any" the gateway refuses hosts that resolve to addresses
// it should not be reachable as: loopback, RFC1918, link-local, the cloud
// metadata service, IPv6 loopback / ULA. Without this check an
// authenticated user can use the gateway as a generic TCP relay against
// any internal target the gateway can reach.
func TestGetHostAnyRejectsSensitiveDestinations(t *testing.T) {
	cases := []struct {
		name string
		host string
	}{
		{"loopback v4", "127.0.0.1:3389"},
		{"loopback name", "localhost:3389"},
		{"cloud metadata", "169.254.169.254:80"},
		{"rfc1918 10/8", "10.0.0.5:3389"},
		{"rfc1918 192.168/16", "192.168.1.10:3389"},
		{"rfc1918 172.16/12", "172.16.5.10:3389"},
		{"ipv6 loopback", "[::1]:3389"},
		{"ipv6 ula", "[fc00::1]:3389"},
		{"non-rdp port on public host", "203.0.113.5:6379"},
	}

	c := Config{
		HostSelection: "any",
		Hosts:         hosts,
	}
	h := c.NewHandler()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := &url.URL{Host: "example.com"}
			vals := u.Query()
			vals.Set("host", tc.host)
			u.RawQuery = vals.Encode()

			got, err := h.getHost(context.Background(), u)
			if err == nil {
				t.Errorf("getHost(%q) returned %q with no error; sensitive destinations must be refused in 'any' mode", tc.host, got)
			}
		})
	}
}

// TestGetHostAnyAllowsExplicitOptIn confirms that an operator can re-enable
// access to private destinations and additional ports for `any` mode when
// the deployment legitimately needs it.
func TestGetHostAnyAllowsExplicitOptIn(t *testing.T) {
	c := Config{
		HostSelection:            "any",
		Hosts:                    hosts,
		AllowedDestinationPorts:  []int{3389, 5985},
		AllowPrivateDestinations: true,
	}
	h := c.NewHandler()

	for _, target := range []string{"10.0.0.1:3389", "127.0.0.1:5985"} {
		u := &url.URL{Host: "example.com"}
		vals := u.Query()
		vals.Set("host", target)
		u.RawQuery = vals.Encode()

		got, err := h.getHost(context.Background(), u)
		if err != nil {
			t.Errorf("getHost(%q) rejected with %v; explicit opt-in must allow private and extra-port destinations", target, err)
		}
		if got != target {
			t.Errorf("getHost(%q) = %q, want unchanged", target, got)
		}
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

func TestHandler_HandleDownload_RdpOverrides(t *testing.T) {
	tests := []struct {
		name        string
		query       string
		allow       []string
		template    string
		wantStatus  int
		wantContain []string // substrings expected in body when status==200
		wantMissing []string
	}{
		{
			name:        "allowed bool override applies",
			query:       "?usemultimon=1",
			allow:       []string{"use multimon"},
			wantStatus:  http.StatusOK,
			wantContain: []string{"use multimon:i:1\r\n"},
		},
		{
			name:        "allowed bool override emits default value explicitly",
			query:       "?usemultimon=0",
			allow:       []string{"use multimon"},
			wantStatus:  http.StatusOK,
			wantContain: []string{"use multimon:i:0\r\n"},
		},
		{
			name:        "override beats template",
			query:       "?usemultimon=0",
			allow:       []string{"use multimon"},
			template:    "use multimon:i:1\r\n",
			wantStatus:  http.StatusOK,
			wantContain: []string{"use multimon:i:0\r\n"},
			wantMissing: []string{"use multimon:i:1\r\n"},
		},
		{
			name:       "no allow list disables overrides",
			query:      "?usemultimon=1",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "key not in allow list is rejected",
			query:      "?audiomode=2",
			allow:      []string{"use multimon"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid bool value rejected",
			query:      "?usemultimon=hello",
			allow:      []string{"use multimon"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid int value rejected",
			query:      "?audiomode=loud",
			allow:      []string{"audiomode"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:        "allow list normalizes (caller uses url-friendly form)",
			query:       "?usemultimon=1",
			allow:       []string{"USE MULTIMON"},
			wantStatus:  http.StatusOK,
			wantContain: []string{"use multimon:i:1\r\n"},
		},
		{
			name:        "unrelated query params are ignored",
			query:       "?host=10.0.0.1:3389&usemultimon=1",
			allow:       []string{"use multimon"},
			wantStatus:  http.StatusOK,
			wantContain: []string{"use multimon:i:1\r\n"},
		},
		{
			name:        "string field override applies",
			query:       "?alternateshell=explorer.exe",
			allow:       []string{"alternate shell"},
			wantStatus:  http.StatusOK,
			wantContain: []string{"alternate shell:s:explorer.exe\r\n"},
		},
		{
			name:        "url override cannot escape authoritative server fields",
			query:       "?username=evil@attacker",
			allow:       []string{"username"}, // operator footgun: still must not leak past server set
			wantStatus:  http.StatusOK,
			wantContain: []string{"username:s:" + testuser + "\r\n"},
			wantMissing: []string{"username:s:evil@attacker\r\n"},
		},
	}

	u, _ := url.Parse(gateway)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/connect"+tt.query, nil)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			id := identity.NewUser()
			id.SetUserName(testuser)
			id.SetAuthenticated(true)
			req = identity.AddToRequestCtx(id, req)

			var templateFile string
			if tt.template != "" {
				f, err := os.CreateTemp("", "rdp")
				if err != nil {
					t.Fatal(err)
				}
				defer os.Remove(f.Name())
				if _, err := f.WriteString(tt.template); err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
				templateFile = f.Name()
			}

			c := Config{
				HostSelection:     "roundrobin",
				Hosts:             hosts,
				PAATokenGenerator: paaTokenMock,
				GatewayAddress:    u,
				RdpOpts:           RdpOpts{OverridableRdpKeys: tt.allow},
				TemplateFile:      templateFile,
			}
			h := c.NewHandler()
			http.HandlerFunc(h.HandleDownload).ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status: got %d, want %d (body=%q)", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if rr.Code != http.StatusOK {
				return
			}
			body := rr.Body.String()
			for _, s := range tt.wantContain {
				if !strings.Contains(body, s) {
					t.Errorf("body missing %q\nbody=\n%s", s, body)
				}
			}
			for _, s := range tt.wantMissing {
				if strings.Contains(body, s) {
					t.Errorf("body contains forbidden %q\nbody=\n%s", s, body)
				}
			}
		})
	}
}

func TestHandler_HandleSignedDownload_RdpOverrideApplies(t *testing.T) {
	// The override must take effect on the signed path too: ApplyOverrides
	// runs on the same Builder used to render the signed content.
	req, err := http.NewRequest("GET", "/connect?usemultimon=1", nil)
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
		HostSelection:     "roundrobin",
		Hosts:             hosts,
		PAATokenGenerator: paaTokenMock,
		GatewayAddress:    u,
		RdpOpts:           RdpOpts{OverridableRdpKeys: []string{"use multimon"}},
	}
	h := c.NewHandler()

	fs := afero.NewMemMapFs()
	if err := genKeypair(fs); err != nil {
		t.Fatalf("could not generate key pair: %s", err)
	}
	signer, err := rdpsign.New("test.crt", "test.key", rdpsign.WithFs(fs))
	if err != nil {
		t.Fatalf("could not create signer: %s", err)
	}
	h.rdpSigner = signer

	http.HandlerFunc(h.HandleDownload).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body=%q)", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "use multimon:i:1\r\n") {
		t.Errorf("signed body missing use multimon:i:1\nbody=\n%s", body)
	}
	if !strings.Contains(body, "signature:s:") {
		t.Errorf("signed body missing signature\nbody=\n%s", body)
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
		HostSelection:     "roundrobin",
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
		HostSelection:     "roundrobin",
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
