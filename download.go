package main

import (
	"encoding/hex"
	"encoding/json"
	"github.com/patrickmn/go-cache"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

const state = "thisismystatebutshouldberandom"

func handleRdpDownload(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("RDPGWSESSIONV1")
	if err != nil {
		http.Redirect(w, r, oauthConfig.AuthCodeURL(state), http.StatusFound)
		return
	}

	data, found := tokens.Get(cookie.Value)
	if found == false {
		log.Printf("Found expired or non existent session: %s", cookie.Value)
		http.Redirect(w, r, oauthConfig.AuthCodeURL(state), http.StatusFound)
		return
	}

	host := strings.Replace(viper.GetString("hostTemplate"), "%%", data.(string), 1)

	// authenticated
	seed := make([]byte, 16)
	rand.Read(seed)
	fn := hex.EncodeToString(seed) + ".rdp"

	w.Header().Set("Content-Disposition", "attachment; filename="+fn)
	w.Header().Set("Content-Type", "application/x-rdp")
	http.ServeContent(w, r, fn, time.Now(), strings.NewReader(
		"full address:s:" + host + "\r\n"+
			"gatewayhostname:s:" + net.JoinHostPort(conf.Server.GatewayAddress, string(conf.Server.Port)) +"\r\n"+
			"gatewaycredentialssource:i:5\r\n"+
			"gatewayusagemethod:i:1\r\n"+
			"gatewayaccesstoken:s:" + cookie.Value + "\r\n"))
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("state") != state {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}

	oauthToken, err := oauthConfig.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{oauthToken, new(json.RawMessage)}

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

	cookie := http.Cookie{
		Name: "RDPGWSESSIONV1",
		Value: token,
		Path: "/",
		Secure: true,
		HttpOnly: true,
	}

	// TODO: make dynamic
	tokens.Set(token, data["preferred_username"].(string), cache.DefaultExpiration)

	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/connect", http.StatusFound)
}