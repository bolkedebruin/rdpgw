package web

import (
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

func (a *AuthMux) Route(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if h == "" {
			for _, s := range a.headers {
				w.Header().Add("WWW-Authenticate", s)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
