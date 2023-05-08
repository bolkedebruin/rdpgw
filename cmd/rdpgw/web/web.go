package web

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/config/parsers"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/rdp"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"hash/maphash"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type TokenGeneratorFunc func(context.Context, string, string) (string, error)
type UserTokenGeneratorFunc func(context.Context, string) (string, error)
type QueryInfoFunc func(context.Context, string, string) (string, error)

type Config struct {
	PAATokenGenerator  TokenGeneratorFunc
	UserTokenGenerator UserTokenGeneratorFunc
	QueryInfo          QueryInfoFunc
	QueryTokenIssuer   string
	EnableUserToken    bool
	Hosts              []string
	HostSelection      string
	GatewayAddress     *url.URL
	RdpOpts            RdpOpts
	TemplateFile       string
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
	paaTokenGenerator  TokenGeneratorFunc
	enableUserToken    bool
	userTokenGenerator UserTokenGeneratorFunc
	queryInfo          QueryInfoFunc
	queryTokenIssuer   string
	gatewayAddress     *url.URL
	hosts              []string
	hostSelection      string
	rdpOpts            RdpOpts
	rdpDefaults        string
}

func (c *Config) NewHandler() *Handler {
	if len(c.Hosts) < 1 {
		log.Fatal("Not enough hosts to connect to specified")
	}

	return &Handler{
		paaTokenGenerator:  c.PAATokenGenerator,
		enableUserToken:    c.EnableUserToken,
		userTokenGenerator: c.UserTokenGenerator,
		queryInfo:          c.QueryInfo,
		queryTokenIssuer:   c.QueryTokenIssuer,
		gatewayAddress:     c.GatewayAddress,
		hosts:              c.Hosts,
		hostSelection:      c.HostSelection,
		rdpOpts:            c.RdpOpts,
		rdpDefaults:        c.TemplateFile,
	}
}

func (h *Handler) selectRandomHost() string {
	r := rand.New(rand.NewSource(int64(new(maphash.Hash).Sum64())))
	host := h.hosts[r.Intn(len(h.hosts))]
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
	id := identity.FromRequestCtx(r)
	ctx := r.Context()

	opts := h.rdpOpts

	if !id.Authenticated() {
		log.Printf("unauthenticated user %s", id.UserName())
		http.Error(w, errors.New("cannot find session or user").Error(), http.StatusInternalServerError)
		return
	}

	// determine host to connect to
	host, err := h.getHost(ctx, r.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	host = strings.Replace(host, "{{ preferred_username }}", id.UserName(), 1)

	// split the username into user and domain
	var user = id.UserName()
	var domain = opts.DefaultDomain
	if opts.SplitUserDomain {
		creds := strings.SplitN(id.UserName(), "@", 2)
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

	d := rdp.NewRdp()

	if h.rdpDefaults != "" {
		var k = koanf.New(".")
		if err := k.Load(file.Provider(h.rdpDefaults), parsers.Parser()); err != nil {
			log.Fatalf("cannot load rdp template file from %s", h.rdpDefaults)
		}
		tag := koanf.UnmarshalConf{Tag: "rdp"}
		k.UnmarshalWithConf("", &d.Settings, tag)
	}

	d.Settings.Username = render
	d.Settings.Domain = domain
	d.Settings.FullAddress = host
	d.Settings.GatewayHostname = h.gatewayAddress.Host
	d.Settings.GatewayCredentialsSource = rdp.SourceCookie
	d.Settings.GatewayAccessToken = token
	d.Settings.GatewayCredentialMethod = 1
	d.Settings.GatewayUsageMethod = 1

	http.ServeContent(w, r, fn, time.Now(), strings.NewReader(d.String()))
}
