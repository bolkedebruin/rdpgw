package main

import (
	"context"
	"crypto/tls"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

var cmd = &cobra.Command{
	Use:	"rdpgw",
	Long:	"Remote Desktop Gateway",
}

var (
	port		int
	certFile	string
	keyFile		string

	configFile	string
)

var tokens = cache.New(time.Minute *5, 10*time.Minute)

var state string

var oauthConfig oauth2.Config
var oidcConfig *oidc.Config
var verifier *oidc.IDTokenVerifier
var ctx context.Context

var gateway string
var overrideHost bool
var hostTemplate string
var claim string

func main() {
	// get config
	cmd.PersistentFlags().IntVarP(&port, "port", "p", 443, "port to listen on for incoming connection")
	cmd.PersistentFlags().StringVarP(&certFile, "certfile", "", "server.pem", "public key certificate file")
	cmd.PersistentFlags().StringVarP(&keyFile, "keyfile", "", "key.pem", "private key file")
	cmd.PersistentFlags().StringVarP(&configFile, "conf", "c", "rdpgw.yaml",  "config file (json, yaml, ini)")
	cmd.PersistentFlags().StringVarP(&gateway, "gateway", "g", "localhost",  "gateway dns name")
	cmd.PersistentFlags().BoolVarP(&overrideHost, "hostOverride", "", false, "weather the user can override the host to connect to")
	cmd.PersistentFlags().StringVarP(&hostTemplate, "hostTemplate", "t", "", "host template")
	cmd.PersistentFlags().StringVarP(&claim, "claim", "", "preferred_username", "openid claim to use for filling in template")

	viper.BindPFlag("port", cmd.PersistentFlags().Lookup("port"))
	viper.BindPFlag("certfile", cmd.PersistentFlags().Lookup("certfile"))
	viper.BindPFlag("keyfile", cmd.PersistentFlags().Lookup("keyfile"))
	viper.BindPFlag("gateway", cmd.PersistentFlags().Lookup("gateway"))
	viper.BindPFlag("hostOverride", cmd.PersistentFlags().Lookup("hostOverride"))
	viper.BindPFlag("hostTemplate", cmd.PersistentFlags().Lookup("hostTemplate"))
	viper.BindPFlag("claim", cmd.PersistentFlags().Lookup("claim"))

	viper.SetConfigName("rdpgw")
	//viper.SetConfigFile(configFile)
	viper.AddConfigPath(".")
	viper.SetEnvPrefix("RDPGW")
	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		log.Printf("No config file found. Using defaults")
	}

	// dont understand why I need to do this
	gateway = viper.GetString("gateway")
	hostTemplate = viper.GetString("hostTemplate")
	overrideHost = viper.GetBool("hostOverride")

	// set oidc config
	ctx = context.Background()
	provider, err := oidc.NewProvider(ctx, viper.GetString("providerUrl"))
	if err != nil {
		log.Fatalf("Cannot get oidc provider: %s", err)
	}
	oidcConfig = &oidc.Config{
		ClientID: viper.GetString("clientId"),
	}
	verifier = provider.Verifier(oidcConfig)

	oauthConfig = oauth2.Config{
		ClientID: viper.GetString("clientId"),
		ClientSecret: viper.GetString("clientSecret"),
		RedirectURL: "https://" + gateway + "/callback",
		Endpoint: provider.Endpoint(),
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// check what is required
	state = "rdpstate"

	if certFile == "" || keyFile == "" {
		log.Fatal("Both certfile and keyfile need to be specified")
	}

	//mux := http.NewServeMux()
	//mux.HandleFunc("*", HelloServer)

	log.Printf("Starting remote desktop gateway server")
	cfg := &tls.Config{}
	tlsDebug := os.Getenv("SSLKEYLOGFILE")
	if tlsDebug != "" {
		w, err := os.OpenFile(tlsDebug, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatalf("Cannot open key log file %s for writing %s", tlsDebug, err)
		}
		log.Printf("Key log file set to: %s", tlsDebug)
		cfg.KeyLogWriter = w
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}
	cfg.Certificates = append(cfg.Certificates, cert)
	server := http.Server{
		Addr:      ":" + strconv.Itoa(port),
		TLSConfig: cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)), // disable http2
	}

	http.HandleFunc("/remoteDesktopGateway/", handleGatewayProtocol)
	http.HandleFunc("/connect", handleRdpDownload)
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/callback", handleCallback)

	prometheus.MustRegister(connectionCache)
	prometheus.MustRegister(legacyConnections)
	prometheus.MustRegister(websocketConnections)

	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
