package web

import (
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/jcmturner/goidentity/v6"
	"log"
	"net"
	"net/http"
	"strings"
)

func EnrichContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := GetSessionIdentity(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if id == nil {
			id = identity.NewUser()
			if err := SaveSessionIdentity(r, w, id); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		log.Printf("Identity SessionId: %s, UserName: %s: Authenticated: %t: Path: %s",
			id.SessionId(), id.UserName(), id.Authenticated(), r.RequestURI)

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
			id.SetAttribute(identity.AttrClientIp, clientIp)
			id.SetAttribute(identity.AttrProxies, proxies)
		}

		id.SetAttribute(identity.AttrRemoteAddr, r.RemoteAddr)
		if h == "" {
			clientIp, _, _ := net.SplitHostPort(r.RemoteAddr)
			id.SetAttribute(identity.AttrClientIp, clientIp)
		}
		next.ServeHTTP(w, identity.AddToRequestCtx(id, r))
	})
}

func TransposeSPNEGOContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gid := goidentity.FromHTTPRequestContext(r)
		if gid != nil {
			id := identity.FromRequestCtx(r)
			id.SetUserName(gid.UserName())
			id.SetAuthenticated(gid.Authenticated())
			id.SetDomain(gid.Domain())
			id.SetAuthTime(gid.AuthTime())
			r = identity.AddToRequestCtx(id, r)
		}
		next.ServeHTTP(w, r)
	})
}
