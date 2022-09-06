package web

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"
	"math/rand"
	"net/http"
	"time"
)

const (
	CacheExpiration = time.Minute * 2
	CleanupInterval = time.Minute * 5
)

type OIDC struct {
	oAuth2Config      *oauth2.Config
	oidcTokenVerifier *oidc.IDTokenVerifier
	stateStore        *cache.Cache
	sessionStore      sessions.Store
}

type OIDCConfig struct {
	OAuth2Config      *oauth2.Config
	OIDCTokenVerifier *oidc.IDTokenVerifier
	SessionStore      sessions.Store
}

func (c *OIDCConfig) New() *OIDC {
	return &OIDC{
		oAuth2Config:      c.OAuth2Config,
		oidcTokenVerifier: c.OIDCTokenVerifier,
		stateStore:        cache.New(CacheExpiration, CleanupInterval),
		sessionStore:      c.SessionStore,
	}
}

func (h *OIDC) HandleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	s, found := h.stateStore.Get(state)
	if !found {
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}
	url := s.(string)

	ctx := r.Context()
	oauth2Token, err := h.oAuth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	idToken, err := h.oidcTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{oauth2Token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal(*resp.IDTokenClaims, &data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, err := h.sessionStore.Get(r, RdpGwSession)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Options.MaxAge = MaxAge
	session.Values["preferred_username"] = data["preferred_username"]
	session.Values["authenticated"] = true
	session.Values["access_token"] = oauth2Token.AccessToken

	if err = session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	http.Redirect(w, r, url, http.StatusFound)
}

func (h *OIDC) Authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := h.sessionStore.Get(r, RdpGwSession)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		found := session.Values["authenticated"]
		if found == nil || !found.(bool) {
			seed := make([]byte, 16)
			rand.Read(seed)
			state := hex.EncodeToString(seed)
			h.stateStore.Set(state, r.RequestURI, cache.DefaultExpiration)
			http.Redirect(w, r, h.oAuth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		ctx := context.WithValue(r.Context(), "preferred_username", session.Values["preferred_username"])
		ctx = context.WithValue(ctx, "access_token", session.Values["access_token"])

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
