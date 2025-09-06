package web

import (
	"github.com/gorilla/mux"
	"net/http"
)

type AuthHeader struct {
	header    string
	condition func(*http.Request) bool
}

type AuthMux struct {
	headers []AuthHeader
}

func NewAuthMux() *AuthMux {
	return &AuthMux{}
}

// Register adds authentication methods with optional condition function
func (a *AuthMux) Register(headers []string, condition func(*http.Request) bool) {
	for _, header := range headers {
		a.headers = append(a.headers, AuthHeader{
			header:    header,
			condition: condition,
		})
	}
}

func (a *AuthMux) SetAuthenticate(w http.ResponseWriter, r *http.Request) {
	for _, authHeader := range a.headers {
		// If condition is nil or condition returns true, add the header
		if authHeader.condition == nil || authHeader.condition(r) {
			w.Header().Add("WWW-Authenticate", authHeader.header)
		}
	}
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func NoAuthz(r *http.Request, rm *mux.RouteMatch) bool {
	return r.Header.Get("Authorization") == ""
}
