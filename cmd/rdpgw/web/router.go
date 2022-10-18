package web

import (
	"github.com/gorilla/mux"
	"net/http"
)

type AuthMux struct {
	headers []string
}

func NewAuthMux() *AuthMux {
	return &AuthMux{}
}

func (a *AuthMux) Register(s string) {
	a.headers = append(a.headers, s)
}

func (a *AuthMux) SetAuthenticate(w http.ResponseWriter, r *http.Request) {
	for _, s := range a.headers {
		w.Header().Add("WWW-Authenticate", s)
	}
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func NoAuthz(r *http.Request, rm *mux.RouteMatch) bool {
	return r.Header.Get("Authorization") == ""
}
