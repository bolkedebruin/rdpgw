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
	"strconv"
	"strings"
	"time"
)

const (
	RdpGwSession = "RDPGWSESSION"
)

type TokenGeneratorFunc func(string, string) (string, error)

type Config struct {
	SessionKey           []byte
	SessionEncryptionKey []byte
	TokenGenerator       TokenGeneratorFunc
	OAuth2Config         *oauth2.Config
	store                *sessions.CookieStore
	TokenVerifier        *oidc.IDTokenVerifier
	stateStore           *cache.Cache
	Hosts                []string
	GatewayAddress       string
	UsernameTemplate     string
	NetworkAutoDetect    int
	BandwidthAutoDetect  int
	ConnectionType       int
}

func (c *Config) NewApi() {
	if len(c.SessionKey) < 32 {
		log.Fatal("Session key too small")
	}
	if len(c.Hosts) < 1 {
		log.Fatal("Not enough hosts to connect to specified")
	}
	c.store = sessions.NewCookieStore(c.SessionKey, c.SessionEncryptionKey)
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

	session, err := c.store.Get(r, RdpGwSession)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["preferred_username"] = data["preferred_username"]
	session.Values["authenticated"] = true

	if err = session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	http.Redirect(w, r, url, http.StatusFound)
}

func (c *Config) Authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := c.store.Get(r, RdpGwSession)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		found := session.Values["authenticated"]
		if found == nil || !found.(bool) {
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

	userName := session.Values["preferred_username"]
	if userName == nil || userName.(string) == "" {
		// This shouldnt happen if the Authenticated handler is used to wrap this func
		log.Printf("Found expired or non existent session")
		http.Error(w, errors.New("cannot find session").Error(), http.StatusInternalServerError)
		return
	}

	// do a round robin selection for now
	rand.Seed(time.Now().Unix())
	host := c.Hosts[rand.Intn(len(c.Hosts))]
	host = strings.Replace(host, "{{ preferred_username }}", userName.(string), 1)

	user := userName.(string)
	if c.UsernameTemplate != "" {
		user = strings.Replace(c.UsernameTemplate, "{{ username }}", user, 1)
		if c.UsernameTemplate == user {
			log.Printf("Invalid username template. %s == %s", c.UsernameTemplate, user)
			http.Error(w, errors.New("invalid server configuration").Error(), http.StatusInternalServerError)
			return
		}
	}

	token, err := c.TokenGenerator(user, host)
	if err != nil {
		log.Printf("Cannot generate token for user %s due to %s", user, err)
		http.Error(w, errors.New("unable to generate gateway credentials").Error(), http.StatusInternalServerError)
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
			"gatewayaccesstoken:s:"+token+"\r\n"+
			"networkautodetect:i:"+strconv.Itoa(c.NetworkAutoDetect)+"\r\n"+
			"bandwidthautodetect:i:"+strconv.Itoa(c.BandwidthAutoDetect)+"\r\n"+
			"connection type:i:"+strconv.Itoa(c.ConnectionType)+"\r\n"+
			"username:s:"+user+"\r\n"))
}
