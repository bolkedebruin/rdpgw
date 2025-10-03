package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	CacheExpiration = time.Minute * 2
	CleanupInterval = time.Minute * 5
	oidcStateKey    = "OIDCSTATE"
)

type OIDC struct {
	oAuth2Config      *oauth2.Config
	oidcTokenVerifier *oidc.IDTokenVerifier
}

type OIDCConfig struct {
	OAuth2Config      *oauth2.Config
	OIDCTokenVerifier *oidc.IDTokenVerifier
}

func (c *OIDCConfig) New() *OIDC {
	return &OIDC{
		oAuth2Config:      c.OAuth2Config,
		oidcTokenVerifier: c.OIDCTokenVerifier,
	}
}

// storeOIDCState stores the OIDC state and redirect URL in the session
func storeOIDCState(w http.ResponseWriter, r *http.Request, state string, redirectURL string) error {
	session, err := GetSession(r)
	if err != nil {
		return err
	}

	// Store state data directly as a concatenated string: state + "|" + redirectURL
	stateValue := state + "|" + redirectURL
	session.Values[oidcStateKey] = stateValue
	session.Options.MaxAge = int(CacheExpiration.Seconds())

	return sessionStore.Save(r, w, session)
}

// getOIDCState retrieves the redirect URL for the given state from the session
func getOIDCState(r *http.Request, state string) (string, bool) {
	session, err := GetSession(r)
	if err != nil {
		log.Printf("Error getting session for OIDC state: %v", err)
		return "", false
	}

	stateData, exists := session.Values[oidcStateKey]
	if !exists {
		log.Printf("No OIDC state data found in session")
		return "", false
	}

	stateValue, ok := stateData.(string)
	if !ok {
		log.Printf("Invalid OIDC state data format in session")
		return "", false
	}

	// Parse state data: state + "|" + redirectURL
	expectedPrefix := state + "|"
	if !strings.HasPrefix(stateValue, expectedPrefix) {
		log.Printf("OIDC state '%s' not found in session", state)
		return "", false
	}

	redirectURL := stateValue[len(expectedPrefix):]
	return redirectURL, true
}

func (h *OIDC) HandleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	url, found := getOIDCState(r, state)
	if !found {
		log.Printf("OIDC HandleCallback: unknown state '%s'", state)
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}

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
		http.Error(w, "no oidc claim for username found", http.StatusInternalServerError)
	}

	id.SetUserName(userName)
	id.SetAuthenticated(true)
	id.SetAuthTime(time.Now())
	id.SetAttribute(identity.AttrAccessToken, oauth2Token.AccessToken)

	if err := SaveSessionIdentity(r, w, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	http.Redirect(w, r, url, http.StatusFound)
}

func findUsernameInClaims(data map[string]interface{}) string {
	candidates := []string{"preferred_username", "unique_name", "upn", "username"}
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
			_, err := rand.Read(seed)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			state := hex.EncodeToString(seed)

			log.Printf("OIDC Authenticated: storing state '%s' for redirect to '%s'", state, r.RequestURI)
			err = storeOIDCState(w, r, state, r.RequestURI)
			if err != nil {
				log.Printf("OIDC Authenticated: failed to store state: %v", err)
				http.Error(w, "Failed to store OIDC state", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, h.oAuth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		// replace the identity with the one from the sessions
		next.ServeHTTP(w, r)
	})
}
