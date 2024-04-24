package web

import (
	"context"
        "errors"
        "github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/shared/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
        "log"
	"net"
        "net/http"
        "time"
)

type ntlmAuthMode uint32
const (
        authNone ntlmAuthMode = iota
        authNTLM
        authNegotiate
)

type NTLMAuthHandler struct {
	SocketAddress string
	Timeout       int
}

func (h *NTLMAuthHandler) NTLMAuth(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
		authPayload, authMode, err := h.getAuthPayload(r)
                if err != nil {
                        log.Printf("Failed parsing auth header: %s", err)
			h.requestAuthenticate(w)
                        return
		}

		authenticated, username := h.authenticate(w, r, authPayload, authMode)

		if authenticated {
			log.Printf("NTLM: User %s authenticated", username)
			id := identity.FromRequestCtx(r)
			id.SetUserName(username)
			id.SetAuthenticated(true)
			id.SetAuthTime(time.Now())
			next.ServeHTTP(w, identity.AddToRequestCtx(id, r))
		}
        }
}

func (h *NTLMAuthHandler) getAuthPayload (r *http.Request) (payload string, authMode ntlmAuthMode, err error) {
	authorisationEncoded := r.Header.Get("Authorization")
	if authorisationEncoded[0:5] == "NTLM " {
		return authorisationEncoded[5:], authNTLM, nil
	}
	if authorisationEncoded[0:10] == "Negotiate " {
		return authorisationEncoded[10:], authNegotiate, nil
	}
	return "", authNone, errors.New("Invalid NTLM Authorisation header")
}

func (h *NTLMAuthHandler) requestAuthenticate (w http.ResponseWriter) {
	w.Header().Add("WWW-Authenticate", `NTLM`)
	w.Header().Add("WWW-Authenticate", `Negotiate`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func (h *NTLMAuthHandler) getAuthPrefix (authMode ntlmAuthMode) (prefix string) {
	if authMode == authNTLM {
		return "NTLM "
	}
	if authMode == authNegotiate {
		return "Negotiate "
	}
	return ""
}

func (h *NTLMAuthHandler) authenticate(w http.ResponseWriter, r *http.Request, authorisationEncoded string, authMode ntlmAuthMode) (authenticated bool, username string) {
	if h.SocketAddress == "" {
		return false, ""
	}

	ctx := r.Context()

	conn, err := grpc.Dial(h.SocketAddress, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return net.Dial(protocolGrpc, addr)
		}))
	if err != nil {
		log.Printf("Cannot reach authentication provider: %s", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return false, ""
	}
	defer conn.Close()

	c := auth.NewAuthenticateClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(h.Timeout))
	defer cancel()

	req := &auth.NtlmRequest{Session: r.RemoteAddr, NtlmMessage: authorisationEncoded}
	res, err := c.NTLM(ctx, req)
	if err != nil {
		log.Printf("Error talking to authentication provider: %s", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return false, ""
	}

	if res.NtlmMessage != "" {
		log.Printf("Sending NTLM challenge")
		w.Header().Add("WWW-Authenticate", h.getAuthPrefix(authMode)+res.NtlmMessage)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false, ""
	}

	if !res.Authenticated {
		h.requestAuthenticate(w)
		return false, ""
	}

	return res.Authenticated, res.Username
}
