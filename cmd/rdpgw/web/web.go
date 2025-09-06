package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/maphash"
	"log"
	rnd "math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/andrewheberle/rdpsign"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/config/hostselection"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/rdp"
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
	RdpSigningCert     string
	RdpSigningKey      string
}

type RdpOpts struct {
	UsernameTemplate string
	SplitUserDomain  bool
	NoUsername       bool
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
	rdpSigner          *rdpsign.Signer
}

func (c *Config) NewHandler() *Handler {
	if len(c.Hosts) < 1 && (c.HostSelection != hostselection.Any && c.HostSelection != hostselection.AnySigned) {
		log.Fatalf("Not enough hosts to connect to specified for %s host selection algorithm", c.HostSelection)
	}

	handler := &Handler{
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

	// set up RDP signer if config values are set
	if c.RdpSigningCert != "" && c.RdpSigningKey != "" {
		signer, err := rdpsign.New(c.RdpSigningCert, c.RdpSigningKey)
		if err != nil {
			log.Fatal("Could not set up RDP signer", err)
		}

		handler.rdpSigner = signer
	}

	return handler
}

func (h *Handler) selectRandomHost() string {
	r := rnd.New(rnd.NewSource(int64(new(maphash.Hash).Sum64())))
	host := h.hosts[r.Intn(len(h.hosts))]
	return host
}

func (h *Handler) getHost(ctx context.Context, u *url.URL) (string, error) {
	switch h.hostSelection {
	case hostselection.RoundRobin:
		return h.selectRandomHost(), nil
	case hostselection.AnySigned:
		hosts, ok := u.Query()["host"]
		if !ok {
			return "", errors.New("invalid query parameter")
		}

		return h.queryInfo(ctx, hosts[0], h.queryTokenIssuer)
	case hostselection.Signed:
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
	case hostselection.Unsigned:
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
	case hostselection.Any:
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
	var domain = ""
	if opts.SplitUserDomain {
		creds := strings.SplitN(id.UserName(), "@", 2)
		user = creds[0]
		if len(creds) > 1 {
			domain = creds[1]
		}
	}

	render := user
	if opts.UsernameTemplate != "" {
		render = fmt.Sprint(h.rdpOpts.UsernameTemplate)
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
		return
	}

	if h.enableUserToken {
		userToken, err := h.userTokenGenerator(ctx, user)
		if err != nil {
			log.Printf("Cannot generate token for user %s due to %s", user, err)
			http.Error(w, errors.New("unable to generate gateway credentials").Error(), http.StatusInternalServerError)
			return
		}
		render = strings.Replace(render, "{{ token }}", userToken, 1)
	}

	// authenticated
	seed := make([]byte, 16)
	_, err = rand.Read(seed)
	if err != nil {
		log.Printf("Cannot generate random seed due to %s", err)
		http.Error(w, errors.New("unable to generate random sequence").Error(), http.StatusInternalServerError)
		return
	}
	fn := hex.EncodeToString(seed) + ".rdp"

	w.Header().Set("Content-Disposition", "attachment; filename="+fn)
	w.Header().Set("Content-Type", "application/x-rdp")

	var d *rdp.Builder
	if h.rdpDefaults == "" {
		d = rdp.NewBuilder()
	} else {
		d, err = rdp.NewBuilderFromFile(h.rdpDefaults)
		if err != nil {
			log.Printf("Cannot load RDP template file %s due to %s", h.rdpDefaults, err)
			http.Error(w, errors.New("unable to load RDP template").Error(), http.StatusInternalServerError)
			return
		}
	}

	if !h.rdpOpts.NoUsername {
		d.Settings.Username = render
		if domain != "" {
			d.Settings.Domain = domain
		}
	}
	d.Settings.FullAddress = host
	d.Settings.GatewayHostname = h.gatewayAddress.Host
	d.Settings.GatewayCredentialsSource = rdp.SourceCookie
	d.Settings.GatewayAccessToken = token
	d.Settings.GatewayCredentialMethod = 1
	d.Settings.GatewayUsageMethod = 1

	// no rdp siging so return as-is
	if h.rdpSigner == nil {
		http.ServeContent(w, r, fn, time.Now(), strings.NewReader(d.String()))
		return
	}

	// get rdp content
	rdpContent := d.String()

	// sign rdp content
	signedContent, err := h.rdpSigner.Sign(rdpContent)
	if err != nil {
		log.Printf("Could not sign RDP file due to %s", err)
		http.Error(w, errors.New("could not sign RDP file").Error(), http.StatusInternalServerError)
		return
	}

	// return signd rdp file
	http.ServeContent(w, r, fn, time.Now(), bytes.NewReader(signedContent))
}
