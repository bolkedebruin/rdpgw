package web

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"
	"log"
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
}

type OIDCConfig struct {
	OAuth2Config      *oauth2.Config
	OIDCTokenVerifier *oidc.IDTokenVerifier
}

func (c *OIDCConfig) New() *OIDC {
	return &OIDC{
		oAuth2Config:      c.OAuth2Config,
		oidcTokenVerifier: c.OIDCTokenVerifier,
		stateStore:        cache.New(CacheExpiration, CleanupInterval),
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

	id := identity.FromRequestCtx(r)

	userName := findUsernameInClaims(data)
	if userName == "" {
		err = errors.New("no odic claim for username found")
		log.Print(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	id.SetUserName(userName)
	id.SetAuthenticated(true)
	id.SetAuthTime(time.Now())
	id.SetAttribute(identity.AttrAccessToken, oauth2Token.AccessToken)

	if err = SaveSessionIdentity(r, w, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	http.Redirect(w, r, url, http.StatusFound)
}

func findUsernameInClaims(data map[string]interface{}) string {
	candidates := []string{"preferred_username", "unique_name", "upn"}
	for _, claim := range candidates {
		userName, found := data[claim].(string)
		if found {
			return userName
		}
	}

	return ""
}

func (h *OIDC) Authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identity.FromRequestCtx(r)

		if !id.Authenticated() {
			seed := make([]byte, 16)
			rand.Read(seed)
			state := hex.EncodeToString(seed)
			h.stateStore.Set(state, r.RequestURI, cache.DefaultExpiration)
			http.Redirect(w, r, h.oAuth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		// replace the identity with the one from the sessions
		next.ServeHTTP(w, r)
	})
}
