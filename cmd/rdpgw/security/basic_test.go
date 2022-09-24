package security

import (
	"context"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/common"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"testing"
)

var (
	info = protocol.Tunnel{
		RDGId:        "myid",
		TargetServer: "my.remote.server",
		RemoteAddr:   "10.0.0.1",
		UserName:     "Frank",
	}

	hosts = []string{"localhost:3389", "my-{{ preferred_username }}-host:3389"}
)

func TestCheckHost(t *testing.T) {
	ctx := context.WithValue(context.Background(), common.TunnelCtx, &info)

	Hosts = hosts

	// check any
	HostSelection = "any"
	host := "try.my.server:3389"
	if ok, err := CheckHost(ctx, host); !ok || err != nil {
		t.Fatalf("%s should be allowed with host selection %s (err: %s)", host, HostSelection, err)
	}

	HostSelection = "signed"
	if ok, err := CheckHost(ctx, host); ok || err == nil {
		t.Fatalf("signed host selection isnt supported at the moment")
	}

	HostSelection = "roundrobin"
	if ok, err := CheckHost(ctx, host); ok {
		t.Fatalf("%s should NOT be allowed with host selection %s (err: %s)", host, HostSelection, err)
	}

	host = "my-Frank-host:3389"
	if ok, err := CheckHost(ctx, host); !ok {
		t.Fatalf("%s should be allowed with host selection %s (err: %s)", host, HostSelection, err)
	}

	info.UserName = ""
	ctx = context.WithValue(ctx, "preferred_username", "dummy")
	host = "my-dummy-host:3389"
	if ok, err := CheckHost(ctx, host); !ok {
		t.Fatalf("%s should be allowed with host selection %s (err: %s)", host, HostSelection, err)
	}

}
