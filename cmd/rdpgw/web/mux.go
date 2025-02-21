package web

import (
	"github.com/gorilla/mux"
	"net/http"
)

type authInfo struct {
	headers  []string
	verifier AuthAvailableVerifier
}

type AuthMux struct {
	headers []authInfo
}

type AuthAvailableVerifier func(r *http.Request) bool

func NewAuthMux() *AuthMux {
	return &AuthMux{}
}

func (a *AuthMux) Register(s []string, verifier AuthAvailableVerifier) {
	a.headers = append(a.headers, authInfo{s, verifier})
}

func (a *AuthMux) SetAuthenticate(w http.ResponseWriter, r *http.Request) {
	for _, s := range a.headers {
		if s.verifier == nil || s.verifier(r) { // verify if the auth method works for the target client
			for _, h := range s.headers {
				w.Header().Add("WWW-Authenticate", h)
			}
		}
	}
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func NoAuthz(r *http.Request, rm *mux.RouteMatch) bool {
	return r.Header.Get("Authorization") == ""
}
