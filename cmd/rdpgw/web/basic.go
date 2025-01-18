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

type BasicAuthHandler struct {
	SocketAddress string
	Timeout       int
}

func (h *BasicAuthHandler) BasicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			authenticated := h.authenticate(w, r, username, password)

			if !authenticated {
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

func (h *BasicAuthHandler) authenticate(w http.ResponseWriter, r *http.Request, username string, password string) (authenticated bool) {
        if h.SocketAddress == "" {
                return false
        }

        ctx := r.Context()
        
        conn, err := grpc.Dial(h.SocketAddress, grpc.WithTransportCredentials(insecure.NewCredentials()),
                grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
                        return net.Dial(protocolGrpc, addr)
                }))
        if err != nil {
                log.Printf("Cannot reach authentication provider: %s", err)
                http.Error(w, "Server error", http.StatusInternalServerError)
                return false
        }
        defer conn.Close()
        
        c := auth.NewAuthenticateClient(conn)
        ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(h.Timeout))
        defer cancel()
        
        req := &auth.UserPass{Username: username, Password: password}
        res, err := c.Authenticate(ctx, req)
        if err != nil {
                log.Printf("Error talking to authentication provider: %s", err)
                http.Error(w, "Server error", http.StatusInternalServerError)
                return false
        }
        
        return res.Authenticated
}
