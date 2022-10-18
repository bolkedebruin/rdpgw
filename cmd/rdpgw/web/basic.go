package web

import (
	"context"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/shared/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"net"
	"net/http"
	"time"
)

const (
	protocolGrpc = "unix"
)

type BasicAuthHandler struct {
	SocketAddress string
}

func (h *BasicAuthHandler) BasicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			ctx := r.Context()

			conn, err := grpc.Dial(h.SocketAddress, grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
					return net.Dial(protocolGrpc, addr)
				}))
			if err != nil {
				log.Printf("Cannot reach authentication provider: %s", err)
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}
			defer conn.Close()

			c := auth.NewAuthenticateClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			req := &auth.UserPass{Username: username, Password: password}
			res, err := c.Authenticate(ctx, req)
			if err != nil {
				log.Printf("Error talking to authentication provider: %s", err)
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}

			if !res.Authenticated {
				log.Printf("User %s is not authenticated for this service", username)
			} else {
				log.Printf("User %s authenticated", username)
				id := identity.FromRequestCtx(r)
				id.SetUserName(username)
				id.SetAuthenticated(true)
				id.SetAuthTime(time.Now())
				next.ServeHTTP(w, identity.AddToRequestCtx(id, r))
				return
			}

		}
		// If the Authentication header is not present, is invalid, or the
		// username or password is wrong, then set a WWW-Authenticate
		// header to inform the client that we expect them to use basic
		// authentication and send a 401 Unauthorized response.
		w.Header().Add("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}
