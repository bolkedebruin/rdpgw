package common

import (
	"context"
	"github.com/jcmturner/goidentity/v6"
	"log"
	"net"
	"net/http"
	"strings"
)

const (
	CtxAccessToken = "github.com/bolkedebruin/rdpgw/oidc/access_token"
)

func EnrichContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := FromRequestCtx(r)
		if id == nil {
			id = NewUser()
		}
		log.Printf("Identity SessionId: %s, UserName: %s: Authenticated: %t",
			id.SessionId(), id.UserName(), id.Authenticated())

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
			id.SetAttribute(AttrClientIp, clientIp)
			id.SetAttribute(AttrProxies, proxies)
		}

		id.SetAttribute(AttrRemoteAddr, r.RemoteAddr)
		if h == "" {
			clientIp, _, _ := net.SplitHostPort(r.RemoteAddr)
			id.SetAttribute(AttrClientIp, clientIp)
		}
		next.ServeHTTP(w, AddToRequestCtx(id, r))
	})
}

func FixKerberosContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gid := goidentity.FromHTTPRequestContext(r)
		if gid != nil {
			id := FromRequestCtx(r)
			id.SetUserName(gid.UserName())
			id.SetAuthenticated(gid.Authenticated())
			id.SetDomain(gid.Domain())
			id.SetAuthTime(gid.AuthTime())
			r = AddToRequestCtx(id, r)
		}
		next.ServeHTTP(w, r)
	})
}

func GetAccessToken(ctx context.Context) string {
	token, ok := ctx.Value(CtxAccessToken).(string)
	if !ok {
		log.Printf("cannot get access token from context")
		return ""
	}
	return token
}
