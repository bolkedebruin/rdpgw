package security

import (
	"context"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"testing"
)

var (
	info = protocol.Tunnel{
		RDGId:        "myid",
		TargetServer: "my.remote.server",
		RemoteAddr:   "10.0.0.1",
	}

	hosts = []string{"localhost:3389", "my-{{ preferred_username }}-host:3389"}
)

func TestCheckHost(t *testing.T) {
	info.User = identity.NewUser()
	info.User.SetUserName("MYNAME")

	ctx := context.WithValue(context.Background(), protocol.CtxTunnel, &info)

	Hosts = hosts

	// check any
	HostSelection = "any"
	host := "try.my.server:3389"
	if ok, err := CheckHost(ctx, host); !ok || err != nil {
		t.Fatalf("%s should be allowed with host selection %s (err: %s)", host, HostSelection, err)
	}

	HostSelection = "signed"
	if ok, err := CheckHost(ctx, host); ok || err == nil {
		t.Fatalf("%s should NOT be allowed with host selection %s when it differs from the token host", host, HostSelection)
	}

	HostSelection = "roundrobin"
	if ok, err := CheckHost(ctx, host); ok {
		t.Fatalf("%s should NOT be allowed with host selection %s (err: %s)", host, HostSelection, err)
	}

	host = "my-MYNAME-host:3389"
	if ok, err := CheckHost(ctx, host); !ok {
		t.Fatalf("%s should be allowed with host selection %s (err: %s)", host, HostSelection, err)
	}

}

func TestCheckHostSigned(t *testing.T) {
	prevSel, prevHosts := HostSelection, Hosts
	t.Cleanup(func() { HostSelection, Hosts = prevSel, prevHosts })

	HostSelection = "signed"
	Hosts = []string{"10.0.0.5:3389", "10.0.0.6:3389"}

	newCtx := func(target string) context.Context {
		tun := &protocol.Tunnel{TargetServer: target, User: identity.NewUser()}
		return context.WithValue(context.Background(), protocol.CtxTunnel, tun)
	}

	cases := []struct {
		name   string
		ctx    context.Context
		host   string
		wantOK bool
	}{
		{"token host on allow-list", newCtx("10.0.0.5:3389"), "10.0.0.5:3389", true},
		{"channel host differs from token host", newCtx("10.0.0.5:3389"), "10.0.0.6:3389", false},
		{"token host not on allow-list", newCtx("10.0.0.9:3389"), "10.0.0.9:3389", false},
		{"no target bound in token", newCtx(""), "10.0.0.5:3389", false},
		{"no tunnel in context", context.Background(), "10.0.0.5:3389", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := CheckHost(tc.ctx, tc.host)
			if ok != tc.wantOK {
				t.Fatalf("CheckHost(%s) = %v (err: %v), want %v", tc.host, ok, err, tc.wantOK)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("CheckHost(%s) denied without an error", tc.host)
			}
		})
	}
}
