package main

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/config"
)

func TestListenAddress(t *testing.T) {
	tests := []struct {
		name        string
		bindAddress string
		port        int
		want        string
	}{
		{name: "all interfaces", port: 443, want: ":443"},
		{name: "IPv4", bindAddress: "127.0.0.1", port: 443, want: "127.0.0.1:443"},
		{name: "IPv6", bindAddress: "::1", port: 443, want: "[::1]:443"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := listenAddress(test.bindAddress, test.port); got != test.want {
				t.Fatalf("listenAddress(%q, %d) = %q, want %q", test.bindAddress, test.port, got, test.want)
			}
		})
	}
}

func TestHostnames(t *testing.T) {
	gw, _ := url.Parse("https://gw.example.com:8443/callback")
	v6, _ := url.Parse("https://gw6.example.com")
	got := hostnames(gw, nil, v6)
	want := []string{"gw.example.com", "gw6.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hostnames = %v, want %v", got, want)
	}
}

func TestFamilyGatewayAddresses(t *testing.T) {
	cases := []struct {
		name           string
		tokenAuth      bool
		verifyClientIp bool
		v4, v6         string
		wantV4, wantV6 string
	}{
		{"both set", true, true, "gw4.example.com", "gw6.example.com", "gw4.example.com", "gw6.example.com"},
		{"only ipv6 set", true, true, "", "gw6.example.com", "", "gw6.example.com"},
		{"not set", true, true, "", "", "", ""},
		{"ip check disabled", true, false, "gw4.example.com", "gw6.example.com", "", ""},
		{"token auth disabled", false, true, "gw4.example.com", "gw6.example.com", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var conf config.Configuration
			conf.Caps.TokenAuth = tc.tokenAuth
			conf.Security.VerifyClientIp = tc.verifyClientIp
			conf.Server.GatewayAddressIPv4 = tc.v4
			conf.Server.GatewayAddressIPv6 = tc.v6

			v4, v6 := familyGatewayAddresses(conf)
			if got := hostOf(v4); got != tc.wantV4 {
				t.Errorf("ipv4 = %q, want %q", got, tc.wantV4)
			}
			if got := hostOf(v6); got != tc.wantV6 {
				t.Errorf("ipv6 = %q, want %q", got, tc.wantV6)
			}
		})
	}
}

func hostOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Host
}
