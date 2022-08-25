package main

import (
	"context"
	"crypto/tls"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/api"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/common"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/config"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/thought-machine/go-flags"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
)

var opts struct {
	ConfigFile string `short:"c" long:"conf" default:"rdpgw.yaml" description:"config file (yaml)"`
}

var conf config.Configuration

func main() {
	// get config
	_, err := flags.Parse(&opts)
	if err != nil {
		panic(err)
	}
	conf = config.Load(opts.ConfigFile)

	security.VerifyClientIP = conf.Security.VerifyClientIp

	// set security keys
	security.SigningKey = []byte(conf.Security.PAATokenSigningKey)
	security.EncryptionKey = []byte(conf.Security.PAATokenEncryptionKey)
	security.UserEncryptionKey = []byte(conf.Security.UserTokenEncryptionKey)
	security.UserSigningKey = []byte(conf.Security.UserTokenSigningKey)
	security.QuerySigningKey = []byte(conf.Security.QueryTokenSigningKey)
	security.HostSelection = conf.Server.HostSelection
	security.Hosts = conf.Server.Hosts

	// configure api
	api := &api.Config{
		QueryInfo:            security.QueryInfo,
		QueryTokenIssuer:     conf.Security.QueryTokenIssuer,
		EnableUserToken:      conf.Security.EnableUserToken,
		SessionKey:           []byte(conf.Server.SessionKey),
		SessionEncryptionKey: []byte(conf.Server.SessionEncryptionKey),
		SessionStore:         conf.Server.SessionStore,
		Hosts:                conf.Server.Hosts,
		HostSelection:        conf.Server.HostSelection,
		NetworkAutoDetect:    conf.Client.NetworkAutoDetect,
		UsernameTemplate:     conf.Client.UsernameTemplate,
		BandwidthAutoDetect:  conf.Client.BandwidthAutoDetect,
		ConnectionType:       conf.Client.ConnectionType,
		SplitUserDomain:      conf.Client.SplitUserDomain,
		DefaultDomain:        conf.Client.DefaultDomain,
		SocketAddress:        conf.Server.AuthSocket,
		Authentication:       conf.Server.Authentication,
	}

	if conf.Caps.TokenAuth {
		api.PAATokenGenerator = security.GeneratePAAToken
	}
	if conf.Security.EnableUserToken {
		api.UserTokenGenerator = security.GenerateUserToken
	}

	if conf.Server.Authentication == "openid" {
		// set oidc config
		provider, err := oidc.NewProvider(context.Background(), conf.OpenId.ProviderUrl)
		if err != nil {
			log.Fatalf("Cannot get oidc provider: %s", err)
		}
		oidcConfig := &oidc.Config{
			ClientID: conf.OpenId.ClientId,
		}
		verifier := provider.Verifier(oidcConfig)

		// get callback url and external advertised gateway address
		url, err := url.Parse(conf.Server.GatewayAddress)
		if url.Scheme == "" {
			url.Scheme = "https"
		}
		url.Path = "callback"
		api.GatewayAddress = url.Host

		oauthConfig := oauth2.Config{
			ClientID:     conf.OpenId.ClientId,
			ClientSecret: conf.OpenId.ClientSecret,
			RedirectURL:  url.String(),
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}
		security.OIDCProvider = provider
		security.Oauth2Config = oauthConfig
		api.OAuth2Config = &oauthConfig
		api.OIDCTokenVerifier = verifier
	}
	api.NewApi()

	log.Printf("Starting remote desktop gateway server")
	cfg := &tls.Config{}

	if conf.Server.DisableTLS {
		log.Printf("TLS disabled - rdp gw connections require tls, make sure to have a terminator")
	} else {
		if conf.Server.CertFile == "" || conf.Server.KeyFile == "" {
			log.Fatal("Both certfile and keyfile need to be specified")
		}

		tlsDebug := os.Getenv("SSLKEYLOGFILE")
		if tlsDebug != "" {
			w, err := os.OpenFile(tlsDebug, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				log.Fatalf("Cannot open key log file %s for writing %s", tlsDebug, err)
			}
			log.Printf("Key log file set to: %s", tlsDebug)
			cfg.KeyLogWriter = w
		}

		cert, err := tls.LoadX509KeyPair(conf.Server.CertFile, conf.Server.KeyFile)
		if err != nil {
			log.Fatal(err)
		}
		cfg.Certificates = append(cfg.Certificates, cert)
	}

	server := http.Server{
		Addr:         ":" + strconv.Itoa(conf.Server.Port),
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)), // disable http2
	}

	// create the gateway
	gwConfig := protocol.ServerConf{
		IdleTimeout:   conf.Caps.IdleTimeout,
		TokenAuth:     conf.Caps.TokenAuth,
		SmartCardAuth: conf.Caps.SmartCardAuth,
		RedirectFlags: protocol.RedirectFlags{
			Clipboard:  conf.Caps.EnableClipboard,
			Drive:      conf.Caps.EnableDrive,
			Printer:    conf.Caps.EnablePrinter,
			Port:       conf.Caps.EnablePort,
			Pnp:        conf.Caps.EnablePnp,
			DisableAll: conf.Caps.DisableRedirect,
			EnableAll:  conf.Caps.RedirectAll,
		},
		SendBuf:    conf.Server.SendBuf,
		ReceiveBuf: conf.Server.ReceiveBuf,
	}
	if conf.Caps.TokenAuth {
		gwConfig.VerifyTunnelAuthFunc = security.VerifyPAAToken
		gwConfig.VerifyServerFunc = security.VerifyServerFunc
	} else {
		gwConfig.VerifyServerFunc = security.BasicVerifyServer
	}
	gw := protocol.Gateway{
		ServerConf: &gwConfig,
	}

	if conf.Server.Authentication == "local" {
		http.Handle("/connect", common.EnrichContext(api.BasicAuth(api.HandleDownload)))
		http.Handle("/remoteDesktopGateway/", common.EnrichContext(api.BasicAuth(gw.HandleGatewayProtocol)))
	} else {
		// openid
		http.Handle("/connect", common.EnrichContext(api.Authenticated(http.HandlerFunc(api.HandleDownload))))
		http.HandleFunc("/callback", api.HandleCallback)
	}
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/tokeninfo", api.TokenInfo)

	if conf.Server.DisableTLS {
		err = server.ListenAndServe()
	} else {
		err = server.ListenAndServeTLS("", "")
	}
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
