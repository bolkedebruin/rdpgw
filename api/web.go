package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

const (
	RdpGwSession = "RDPGWSESSION"
	PAAToken     = "PAAToken"
)

type Config struct {
	SessionKey     []byte
	TokenCache     *cache.Cache
	OAuth2Config   *oauth2.Config
	store          *sessions.CookieStore
	TokenVerifier  *oidc.IDTokenVerifier
	stateStore     *cache.Cache
	Hosts          []string
	GatewayAddress string
}

func (c *Config) NewApi() {
	if len(c.SessionKey) < 32 {
		log.Fatal("Session key too small")
	}
	if len(c.Hosts) < 1 {
		log.Fatal("Not enough hosts to connect to specified")
	}
	c.store = sessions.NewCookieStore(c.SessionKey)
	c.stateStore = cache.New(time.Minute*2, 5*time.Minute)
}

func (c *Config) HandleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	s, found := c.stateStore.Get(state)
	if !found {
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}
	url := s.(string)

	ctx := context.Background()
	oauth2Token, err := c.OAuth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	idToken, err := c.TokenVerifier.Verify(ctx, rawIDToken)
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

	seed := make([]byte, 16)
	rand.Read(seed)
	token := hex.EncodeToString(seed)

	session, err := c.store.Get(r, RdpGwSession)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values[PAAToken] = token

	if err = session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	c.TokenCache.Set(token, data, cache.DefaultExpiration)

	http.Redirect(w, r, url, http.StatusFound)
}

func (c *Config) Authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := c.store.Get(r, RdpGwSession)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		found := false
		token := session.Values[PAAToken]
		if token != nil {
			_, found = c.TokenCache.Get(token.(string))
		}

		if !found {
			seed := make([]byte, 16)
			rand.Read(seed)
			state := hex.EncodeToString(seed)
			c.stateStore.Set(state, r.RequestURI, cache.DefaultExpiration)
			http.Redirect(w, r, c.OAuth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (c *Config) HandleDownload(w http.ResponseWriter, r *http.Request) {
	session, err := c.store.Get(r, RdpGwSession)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	token := session.Values[PAAToken].(string)
	data, found := c.TokenCache.Get(token)
	if found == false {
		// This shouldnt happen if the Authenticated handler is used to wrap this func
		log.Printf("Found expired or non existent session: %s", token)
		http.Error(w, errors.New("cannot find token").Error(), http.StatusInternalServerError)
		return
	}

	// do a round robin selection for now
	rand.Seed(time.Now().Unix())
	var host = c.Hosts[rand.Intn(len(c.Hosts))]
	for k, v := range data.(map[string]interface{}) {
		if val, ok := v.(string); ok == true {
			host = strings.Replace(host, "{{ "+k+" }}", val, 1)
		}
	}

	// authenticated
	seed := make([]byte, 16)
	rand.Read(seed)
	fn := hex.EncodeToString(seed) + ".rdp"

	w.Header().Set("Content-Disposition", "attachment; filename="+fn)
	w.Header().Set("Content-Type", "application/x-rdp")
	http.ServeContent(w, r, fn, time.Now(), strings.NewReader(
		"full address:s:"+host+"\r\n"+
			"gatewayhostname:s:"+c.GatewayAddress+"\r\n"+
			"gatewaycredentialssource:i:5\r\n"+
			"gatewayusagemethod:i:1\r\n"+
			"gatewayprofileusagemethod:i:1\r\n"+
			"gatewayaccesstoken:s:"+token+"\r\n"))
}
