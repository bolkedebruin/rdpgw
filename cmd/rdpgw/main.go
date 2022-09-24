package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/common"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/config"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/web"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/thought-machine/go-flags"
	"golang.org/x/crypto/acme/autocert"
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

func initOIDC(callbackUrl *url.URL, store sessions.Store) *web.OIDC {
	// set oidc config
	provider, err := oidc.NewProvider(context.Background(), conf.OpenId.ProviderUrl)
	if err != nil {
		log.Fatalf("Cannot get oidc provider: %s", err)
	}
	oidcConfig := &oidc.Config{
		ClientID: conf.OpenId.ClientId,
	}
	verifier := provider.Verifier(oidcConfig)

	oauthConfig := oauth2.Config{
		ClientID:     conf.OpenId.ClientId,
		ClientSecret: conf.OpenId.ClientSecret,
		RedirectURL:  callbackUrl.String(),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	security.OIDCProvider = provider
	security.Oauth2Config = oauthConfig

	o := web.OIDCConfig{
		OAuth2Config:      &oauthConfig,
		OIDCTokenVerifier: verifier,
		SessionStore:      store,
	}

	return o.New()
}

func main() {
	// load config
	_, err := flags.Parse(&opts)
	if err != nil {
		panic(err)
	}
	conf = config.Load(opts.ConfigFile)

	// set callback url and external advertised gateway address
	url, err := url.Parse(conf.Server.GatewayAddress)
	if err != nil {
		log.Printf("Cannot parse server gateway address %s due to %s", url, err)
	}
	if url.Scheme == "" {
		url.Scheme = "https"
	}
	url.Path = "callback"

	// set security options
	security.VerifyClientIP = conf.Security.VerifyClientIp
	security.SigningKey = []byte(conf.Security.PAATokenSigningKey)
	security.EncryptionKey = []byte(conf.Security.PAATokenEncryptionKey)
	security.UserEncryptionKey = []byte(conf.Security.UserTokenEncryptionKey)
	security.UserSigningKey = []byte(conf.Security.UserTokenSigningKey)
	security.QuerySigningKey = []byte(conf.Security.QueryTokenSigningKey)
	security.HostSelection = conf.Server.HostSelection
	security.Hosts = conf.Server.Hosts

	// init session store
	sessionConf := web.SessionManagerConf{
		SessionKey:           []byte(conf.Server.SessionKey),
		SessionEncryptionKey: []byte(conf.Server.SessionEncryptionKey),
		StoreType:            conf.Server.SessionStore,
	}
	store := sessionConf.Init()

	// configure web backend
	w := &web.Config{
		QueryInfo:        security.QueryInfo,
		QueryTokenIssuer: conf.Security.QueryTokenIssuer,
		EnableUserToken:  conf.Security.EnableUserToken,
		SessionStore:     store,
		Hosts:            conf.Server.Hosts,
		HostSelection:    conf.Server.HostSelection,
		RdpOpts: web.RdpOpts{
			UsernameTemplate:    conf.Client.UsernameTemplate,
			SplitUserDomain:     conf.Client.SplitUserDomain,
			DefaultDomain:       conf.Client.DefaultDomain,
			NetworkAutoDetect:   conf.Client.NetworkAutoDetect,
			BandwidthAutoDetect: conf.Client.BandwidthAutoDetect,
			ConnectionType:      conf.Client.ConnectionType,
		},
		GatewayAddress: url,
	}

	if conf.Caps.TokenAuth {
		w.PAATokenGenerator = security.GeneratePAAToken
	}
	if conf.Security.EnableUserToken {
		w.UserTokenGenerator = security.GenerateUserToken
	}
	h := w.NewHandler()

	log.Printf("Starting remote desktop gateway server")
	cfg := &tls.Config{}

	if conf.Server.Tls == config.TlsDisable {
		log.Printf("TLS disabled - rdp gw connections require tls, make sure to have a terminator")
	} else {
		// auto config
		tlsConfigured := false

		tlsDebug := os.Getenv("SSLKEYLOGFILE")
		if tlsDebug != "" {
			w, err := os.OpenFile(tlsDebug, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				log.Fatalf("Cannot open key log file %s for writing %s", tlsDebug, err)
			}
			log.Printf("Key log file set to: %s", tlsDebug)
			cfg.KeyLogWriter = w
		}

		if conf.Server.KeyFile != "" && conf.Server.CertFile != "" {
			cert, err := tls.LoadX509KeyPair(conf.Server.CertFile, conf.Server.KeyFile)
			if err != nil {
				log.Printf("Cannot load certfile or keyfile (%s) falling back to acme", err)
			}
			cfg.Certificates = append(cfg.Certificates, cert)
			tlsConfigured = true
		}

		if !tlsConfigured {
			log.Printf("Using acme / letsencrypt for tls configuration. Enabling http (port 80) for verification")
			// setup a simple handler which sends a HTHS header for six months (!)
			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Strict-Transport-Security", "max-age=15768000 ; includeSubDomains")
				fmt.Fprintf(w, "Hello from RDPGW")
			})

			certMgr := autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(url.Host),
				Cache:      autocert.DirCache("/tmp/rdpgw"),
			}
			cfg.GetCertificate = certMgr.GetCertificate

			go func() {
				http.ListenAndServe(":80", certMgr.HTTPHandler(nil))
			}()
		}
	}

	server := http.Server{
		Addr:         ":" + strconv.Itoa(conf.Server.Port),
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)), // disable http2
	}

	// create the gateway
	gw := protocol.Gateway{
		RedirectFlags: protocol.RedirectFlags{
			Clipboard:  conf.Caps.EnableClipboard,
			Drive:      conf.Caps.EnableDrive,
			Printer:    conf.Caps.EnablePrinter,
			Port:       conf.Caps.EnablePort,
			Pnp:        conf.Caps.EnablePnp,
			DisableAll: conf.Caps.DisableRedirect,
			EnableAll:  conf.Caps.RedirectAll,
		},
		IdleTimeout:   conf.Caps.IdleTimeout,
		SmartCardAuth: conf.Caps.SmartCardAuth,
		TokenAuth:     conf.Caps.TokenAuth,
		ReceiveBuf:    conf.Server.ReceiveBuf,
		SendBuf:       conf.Server.SendBuf,
	}

	if conf.Caps.TokenAuth {
		gw.CheckPAACookie = security.CheckPAACookie
		gw.CheckHost = security.CheckSession(security.CheckHost)
	} else {
		gw.CheckHost = security.CheckHost
	}
	gwserver = &gw

	if conf.Server.Authentication == config.AuthenticationBasic {
		h := web.BasicAuthHandler{SocketAddress: conf.Server.AuthSocket}
		http.Handle("/remoteDesktopGateway/", common.EnrichContext(h.BasicAuth(gw.HandleGatewayProtocol)))
	} else {
		// openid
		oidc := initOIDC(url, store)
		http.Handle("/connect", common.EnrichContext(oidc.Authenticated(http.HandlerFunc(h.HandleDownload))))
		http.Handle("/remoteDesktopGateway/", common.EnrichContext(http.HandlerFunc(gw.HandleGatewayProtocol)))
		http.HandleFunc("/callback", oidc.HandleCallback)
	}
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/tokeninfo", web.TokenInfo)
	http.HandleFunc("/list", List)

	if conf.Server.Tls == config.TlsDisable {
		err = server.ListenAndServe()
	} else {
		err = server.ListenAndServeTLS("", "")
	}
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

var gwserver *protocol.Gateway

func List(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	for k, v := range protocol.Connections {
		fmt.Fprintf(w, "Id: %s Rdg-Id: %s User: %s From: %s Connected Since: %s Bytes Sent: %d Bytes Received: %d Last Seen: %s Target: %s\n",
			k, v.Tunnel.RDGId, v.Tunnel.UserName, v.Tunnel.RemoteAddr, v.Tunnel.ConnectedOn, v.Tunnel.BytesSent, v.Tunnel.BytesReceived,
			v.Tunnel.LastSeen, v.Tunnel.TargetServer)
	}
}
