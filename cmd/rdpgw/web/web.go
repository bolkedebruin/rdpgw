package web

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gorilla/sessions"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	RdpGwSession = "RDPGWSESSION"
	MaxAge       = 120
)

type TokenGeneratorFunc func(context.Context, string, string) (string, error)
type UserTokenGeneratorFunc func(context.Context, string) (string, error)
type QueryInfoFunc func(context.Context, string, string) (string, error)

type Config struct {
	SessionStore       sessions.Store
	PAATokenGenerator  TokenGeneratorFunc
	UserTokenGenerator UserTokenGeneratorFunc
	QueryInfo          QueryInfoFunc
	QueryTokenIssuer   string
	EnableUserToken    bool
	Hosts              []string
	HostSelection      string
	GatewayAddress     *url.URL
	RdpOpts            RdpOpts
}

type RdpOpts struct {
	UsernameTemplate    string
	SplitUserDomain     bool
	DefaultDomain       string
	NetworkAutoDetect   int
	BandwidthAutoDetect int
	ConnectionType      int
}

type Handler struct {
	sessionStore       sessions.Store
	paaTokenGenerator  TokenGeneratorFunc
	enableUserToken    bool
	userTokenGenerator UserTokenGeneratorFunc
	queryInfo          QueryInfoFunc
	queryTokenIssuer   string
	gatewayAddress     *url.URL
	hosts              []string
	hostSelection      string
	rdpOpts            RdpOpts
}

func (c *Config) NewHandler() *Handler {
	if len(c.Hosts) < 1 {
		log.Fatal("Not enough hosts to connect to specified")
	}
	return &Handler{
		sessionStore:       c.SessionStore,
		paaTokenGenerator:  c.PAATokenGenerator,
		enableUserToken:    c.EnableUserToken,
		userTokenGenerator: c.UserTokenGenerator,
		queryInfo:          c.QueryInfo,
		queryTokenIssuer:   c.QueryTokenIssuer,
		gatewayAddress:     c.GatewayAddress,
		hosts:              c.Hosts,
		hostSelection:      c.HostSelection,
		rdpOpts:            c.RdpOpts,
	}
}

func (h *Handler) selectRandomHost() string {
	rand.Seed(time.Now().Unix())
	host := h.hosts[rand.Intn(len(h.hosts))]
	return host
}

func (h *Handler) getHost(ctx context.Context, u *url.URL) (string, error) {
	switch h.hostSelection {
	case "roundrobin":
		return h.selectRandomHost(), nil
	case "signed":
		hosts, ok := u.Query()["host"]
		if !ok {
			return "", errors.New("invalid query parameter")
		}
		host, err := h.queryInfo(ctx, hosts[0], h.queryTokenIssuer)
		if err != nil {
			return "", err
		}
		found := false
		for _, check := range h.hosts {
			if check == host {
				found = true
				break
			}
		}
		if !found {
			log.Printf("Invalid host %s specified in token", hosts[0])
			return "", errors.New("invalid host specified in query token")
		}
		return host, nil
	case "unsigned":
		hosts, ok := u.Query()["host"]
		if !ok {
			return "", errors.New("invalid query parameter")
		}
		for _, check := range h.hosts {
			if check == hosts[0] {
				return hosts[0], nil
			}
		}
		// not found
		log.Printf("Invalid host %s specified in client request", hosts[0])
		return "", errors.New("invalid host specified in query parameter")
	case "any":
		hosts, ok := u.Query()["host"]
		if !ok {
			return "", errors.New("invalid query parameter")
		}
		return hosts[0], nil
	default:
		return h.selectRandomHost(), nil
	}
}

func (h *Handler) HandleDownload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userName, ok := ctx.Value("preferred_username").(string)

	opts := h.rdpOpts

	if !ok {
		log.Printf("preferred_username not found in context")
		http.Error(w, errors.New("cannot find session or user").Error(), http.StatusInternalServerError)
		return
	}

	// determine host to connect to
	host, err := h.getHost(ctx, r.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	host = strings.Replace(host, "{{ preferred_username }}", userName, 1)

	// split the username into user and domain
	var user = userName
	var domain = opts.DefaultDomain
	if opts.SplitUserDomain {
		creds := strings.SplitN(userName, "@", 2)
		user = creds[0]
		if len(creds) > 1 {
			domain = creds[1]
		}
	}

	render := user
	if opts.UsernameTemplate != "" {
		render = fmt.Sprintf(h.rdpOpts.UsernameTemplate)
		render = strings.Replace(render, "{{ username }}", user, 1)
		if h.rdpOpts.UsernameTemplate == render {
			log.Printf("Invalid username template. %s == %s", h.rdpOpts.UsernameTemplate, user)
			http.Error(w, errors.New("invalid server configuration").Error(), http.StatusInternalServerError)
			return
		}
	}

	token, err := h.paaTokenGenerator(ctx, user, host)
	if err != nil {
		log.Printf("Cannot generate PAA token for user %s due to %s", user, err)
		http.Error(w, errors.New("unable to generate gateway credentials").Error(), http.StatusInternalServerError)
	}

	if h.enableUserToken {
		userToken, err := h.userTokenGenerator(ctx, user)
		if err != nil {
			log.Printf("Cannot generate token for user %s due to %s", user, err)
			http.Error(w, errors.New("unable to generate gateway credentials").Error(), http.StatusInternalServerError)
		}
		render = strings.Replace(render, "{{ token }}", userToken, 1)
	}

	// authenticated
	seed := make([]byte, 16)
	rand.Read(seed)
	fn := hex.EncodeToString(seed) + ".rdp"

	w.Header().Set("Content-Disposition", "attachment; filename="+fn)
	w.Header().Set("Content-Type", "application/x-rdp")

	rdp := NewRdp()
	rdp.Connection.Username = render
	rdp.Connection.Domain = domain
	rdp.Connection.FullAddress = host
	rdp.Connection.GatewayHostname = h.gatewayAddress.Host
	rdp.Connection.GatewayCredentialsSource = SourceCookie
	rdp.Connection.GatewayAccessToken = token
	rdp.Session.NetworkAutodetect = opts.NetworkAutoDetect != 0
	rdp.Session.BandwidthAutodetect = opts.BandwidthAutoDetect != 0
	rdp.Session.ConnectionType = opts.ConnectionType
	rdp.Display.SmartSizing = true
	rdp.Display.BitmapCacheSize = 32000

	http.ServeContent(w, r, fn, time.Now(), strings.NewReader(rdp.String()))
}
