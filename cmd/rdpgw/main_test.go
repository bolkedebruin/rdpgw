package main

import "testing"

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
