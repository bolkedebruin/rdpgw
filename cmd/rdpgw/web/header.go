package web

import (
	"net/http"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

type Header struct {
	userHeader        string
	userIdHeader      string
	emailHeader       string
	displayNameHeader string
}

type HeaderConfig struct {
	UserHeader        string
	UserIdHeader      string
	EmailHeader       string
	DisplayNameHeader string
}

func (c *HeaderConfig) New() *Header {
	return &Header{
		userHeader:        c.UserHeader,
		userIdHeader:      c.UserIdHeader,
		emailHeader:       c.EmailHeader,
		displayNameHeader: c.DisplayNameHeader,
	}
}

// Authenticated middleware that extracts user identity from configurable proxy headers
func (h *Header) Authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identity.FromRequestCtx(r)

		// Check if user is already authenticated
		if id.Authenticated() {
			next.ServeHTTP(w, r)
			return
		}

		// Extract username from configured user header
		userName := r.Header.Get(h.userHeader)
		if userName == "" {
			http.Error(w, "No authenticated user from proxy", http.StatusUnauthorized)
			return
		}

		// Set identity for downstream processing
		id.SetUserName(userName)
		id.SetAuthenticated(true)
		id.SetAuthTime(time.Now())

		// Set optional user attributes from headers
		if h.userIdHeader != "" {
			if userId := r.Header.Get(h.userIdHeader); userId != "" {
				id.SetAttribute("user_id", userId)
			}
		}

		if h.emailHeader != "" {
			if email := r.Header.Get(h.emailHeader); email != "" {
				id.SetEmail(email)
			}
		}

		if h.displayNameHeader != "" {
			if displayName := r.Header.Get(h.displayNameHeader); displayName != "" {
				id.SetDisplayName(displayName)
			}
		}

		// Save the session identity
		if err := SaveSessionIdentity(r, w, id); err != nil {
			http.Error(w, "Failed to save session: "+err.Error(), http.StatusInternalServerError)
			return
		}

		next.ServeHTTP(w, r)
	})
}