package client

import (
	"context"
	"net/http"
	"strings"
)

const (
	ClientIPCtx       = "ClientIP"
	ProxyAddressesCtx = "ProxyAddresses"
	RemoteAddressCtx  = "RemoteAddress"
)

func EnrichContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		h := r.Header.Get("X-Forwarded-For")
		if h != "" {
			var proxies []string
			ips := strings.Split(h, ",")
			for i := range ips {
				ips[i] = strings.TrimSpace(ips[i])
			}
			clientIp := ips[0]
			if len(ips) > 1 {
				proxies = ips[1:]
			}
			ctx = context.WithValue(ctx, ClientIPCtx, clientIp)
			ctx = context.WithValue(ctx, ProxyAddressesCtx, proxies)
		}

		remote := r.Header.Get("REMOTE_ADDR")
		ctx = context.WithValue(ctx, RemoteAddressCtx, remote)
		if h == "" {
			ctx = context.WithValue(ctx, ClientIPCtx, remote)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetClientIp(ctx context.Context) string {
	s, ok := ctx.Value(ClientIPCtx).(string)
	if !ok {
		return ""
	}
	return s
}
