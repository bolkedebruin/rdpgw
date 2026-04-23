package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/maphash"
	"html/template"
	"log"
	rnd "math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
	TemplatesPath      string
}

// WebConfig represents the web interface configuration
type WebConfig struct {
	Branding struct {
		Title     string `json:"title"`
		Logo      string `json:"logo"`
		PageTitle string `json:"page_title"`
	} `json:"branding"`
	Messages struct {
		SelectServer string `json:"select_server"`
		Preparing    string `json:"preparing"`
	} `json:"messages"`
	UI struct {
		ProgressAnimationDurationMs int  `json:"progress_animation_duration_ms"`
		AutoSelectDefault           bool `json:"auto_select_default"`
		ShowUserAvatar              bool `json:"show_user_avatar"`
	} `json:"ui"`
	Theme struct {
		PrimaryColor   string `json:"primary_color"`
		SecondaryColor string `json:"secondary_color"`
		SuccessColor   string `json:"success_color"`
		ErrorColor     string `json:"error_color"`
	} `json:"theme"`
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
	templatesPath      string
	webConfig          *WebConfig
	htmlTemplate       *template.Template
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
		templatesPath:      c.TemplatesPath,
	}

	// set up RDP signer if config values are set
	if c.RdpSigningCert != "" && c.RdpSigningKey != "" {
		signer, err := rdpsign.New(c.RdpSigningCert, c.RdpSigningKey)
		if err != nil {
			log.Fatal("Could not set up RDP signer", err)
		}

		handler.rdpSigner = signer
	}

	// Set up templates path
	if handler.templatesPath == "" {
		handler.templatesPath = "./templates"
	}

	// Load web configuration
	handler.loadWebConfig()

	// Load HTML template
	handler.loadHTMLTemplate()

	return handler
}

// loadWebConfig sets up the web interface configuration with defaults
func (h *Handler) loadWebConfig() {
	// Set defaults - these can be overridden by the main config system later
	h.webConfig = &WebConfig{}
	h.webConfig.Branding.Title = "RDP Gateway"
	h.webConfig.Branding.Logo = "RDP Gateway"
	h.webConfig.Branding.PageTitle = "Select a Server to Connect"
	h.webConfig.Messages.SelectServer = "Select a server to connect"
	h.webConfig.Messages.Preparing = "Preparing your connection..."
	h.webConfig.UI.ProgressAnimationDurationMs = 2000
	h.webConfig.UI.AutoSelectDefault = true
	h.webConfig.UI.ShowUserAvatar = true
	h.webConfig.Theme.PrimaryColor = "#667eea"
	h.webConfig.Theme.SecondaryColor = "#764ba2"
	h.webConfig.Theme.SuccessColor = "#38b2ac"
	h.webConfig.Theme.ErrorColor = "#c53030"
}

// loadHTMLTemplate loads the HTML template
func (h *Handler) loadHTMLTemplate() {
	templatePath := filepath.Join(h.templatesPath, "index.html")

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Printf("Warning: Failed to load HTML template %s: %v", templatePath, err)
		log.Printf("Using embedded fallback template")
		h.htmlTemplate = template.Must(template.New("index").Parse(fallbackHTMLTemplate))
	} else {
		h.htmlTemplate = tmpl
		log.Printf("Loaded HTML template from %s", templatePath)
	}
}

// ServeStaticFile serves static files from the templates directory
func (h *Handler) ServeStaticFile(filename string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filePath := filepath.Join(h.templatesPath, filename)

		// Check if file exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}

		// Set appropriate content type
		switch filepath.Ext(filename) {
		case ".css":
			w.Header().Set("Content-Type", "text/css")
		case ".js":
			w.Header().Set("Content-Type", "application/javascript")
		case ".svg":
			w.Header().Set("Content-Type", "image/svg+xml")
		case ".png":
			w.Header().Set("Content-Type", "image/png")
		case ".jpg", ".jpeg":
			w.Header().Set("Content-Type", "image/jpeg")
		default:
			// Check if it's one of our logo files without extension
			if filename == "logo.png" || filename == "logo_light_background.png" || filename == "logo_dark_background.png" {
				w.Header().Set("Content-Type", "image/png")
			}
		}

		// Enable caching for static files
		w.Header().Set("Cache-Control", "public, max-age=3600")

		http.ServeFile(w, r, filePath)
	}
}

// ServeAssetFile serves asset files from the assets directory
func (h *Handler) ServeAssetFile(filename string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var filePath string

		// Try multiple possible locations for assets
		possiblePaths := []string{
			// Docker container paths
			"./assets/" + filename,
			"/app/assets/" + filename,
			"/opt/rdpgw/assets/" + filename,
			// Development paths
			filepath.Join("assets", filename),
		}

		// Add icon.svg to the check as well
		if filename == "icon.svg" {
			possiblePaths = append(possiblePaths, "./icon.svg", "/app/icon.svg", "/opt/rdpgw/icon.svg")
		}

		// If we have templates path, try relative to it
		if h.templatesPath != "" {
			templatesDir, err := filepath.Abs(h.templatesPath)
			if err == nil {
				// Navigate up from templates to find assets
				currentDir := templatesDir
				for i := 0; i < 5; i++ {
					parentDir := filepath.Dir(currentDir)
					if parentDir == currentDir {
						break
					}
					possiblePaths = append(possiblePaths, filepath.Join(parentDir, "assets", filename))
					currentDir = parentDir
				}
			}
		}

		// Test each possible path
		for _, testPath := range possiblePaths {
			if _, err := os.Stat(testPath); err == nil {
				filePath = testPath
				break
			}
		}

		if filePath == "" {
			log.Printf("Asset file not found: %s. Tried paths: %v", filename, possiblePaths)
			http.NotFound(w, r)
			return
		}

		// Check if file exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}

		// Set appropriate content type
		switch filepath.Ext(filename) {
		case ".svg":
			w.Header().Set("Content-Type", "image/svg+xml")
		case ".png":
			w.Header().Set("Content-Type", "image/png")
		case ".jpg", ".jpeg":
			w.Header().Set("Content-Type", "image/jpeg")
		default:
			// Check if it's one of our asset files without extension
			if filename == "logo_light_background.png" || filename == "logo_dark_background.png" || filename == "connect.svg" {
				if filepath.Ext(filename) == ".png" || filename == "logo_light_background.png" || filename == "logo_dark_background.png" {
					w.Header().Set("Content-Type", "image/png")
				} else {
					w.Header().Set("Content-Type", "image/svg+xml")
				}
			}
		}

		// Enable caching for asset files
		w.Header().Set("Cache-Control", "public, max-age=3600")

		http.ServeFile(w, r, filePath)
	}
}

// fallbackHTMLTemplate is used when external template file is not available
const fallbackHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 800px; margin: 2rem auto; padding: 2rem; background: white; border-radius: 12px; }
        .server-card { border: 2px solid #e2e8f0; border-radius: 8px; padding: 1.5rem; margin: 1rem; cursor: pointer; }
        .server-card:hover { border-color: #667eea; }
        .server-card.selected { border-color: #667eea; background: rgba(102, 126, 234, 0.05); }
        .connect-button { width: 100%; background: #667eea; color: white; border: none; border-radius: 8px;
                         padding: 1rem 2rem; font-size: 1.1rem; cursor: pointer; }
        .connect-button:disabled { background: #a0aec0; cursor: not-allowed; }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{.PageTitle}}</h1>
        <div id="serversGrid"></div>
        <button class="connect-button" id="connectButton" disabled>{{.SelectServerMessage}}</button>
        <div id="loading" style="display:none;">{{.PreparingMessage}}</div>
    </div>
    <script>
        // Fallback minimal JavaScript
        let selectedServer = null;
        async function loadServers() {
            const response = await fetch('/api/hosts');
            const servers = await response.json();
            const grid = document.getElementById('serversGrid');
            servers.forEach(server => {
                const card = document.createElement('div');
                card.className = 'server-card';
                card.innerHTML = server.icon + ' ' + server.name + '<br><small>' + server.description + '</small>';
                card.onclick = () => {
                    document.querySelectorAll('.server-card').forEach(c => c.classList.remove('selected'));
                    card.classList.add('selected');
                    selectedServer = server;
                    document.getElementById('connectButton').disabled = false;
                };
                grid.appendChild(card);
            });
        }
        async function connectToServer() {
            if (!selectedServer) return;
            let url = '/connect';
            if (selectedServer.address) url += '?host=' + encodeURIComponent(selectedServer.address);
            window.location.href = url;
        }
        document.addEventListener('DOMContentLoaded', loadServers);
        document.getElementById('connectButton').onclick = connectToServer;
    </script>
</body>
</html>`

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

// Host represents a host available for connection
type Host struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Address     string `json:"address"`
	Description string `json:"description"`
	IsDefault   bool   `json:"isDefault"`
}

// UserInfo represents the current authenticated user
type UserInfo struct {
	Username      string    `json:"username"`
	Authenticated bool      `json:"authenticated"`
	AuthTime      time.Time `json:"authTime"`
}

// HandleHostList returns the list of available hosts for the authenticated user
func (h *Handler) HandleHostList(w http.ResponseWriter, r *http.Request) {
	id := identity.FromRequestCtx(r)

	if !id.Authenticated() {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var hosts []Host

	// Simplified host selection - all modes work the same for the user
	if h.hostSelection == "roundrobin" {
		hosts = append(hosts, Host{
			ID:          "roundrobin",
			Name:        "Available Servers",
			Address:     "",
			Description: "Connect to an available server automatically",
			IsDefault:   true,
		})
	} else {
		// For all other modes (signed, unsigned, any), show the actual hosts
		for i, hostAddr := range h.hosts {
			hosts = append(hosts, Host{
				ID:          fmt.Sprintf("host_%d", i),
				Name:        hostAddr,
				Address:     hostAddr,
				Description: fmt.Sprintf("Connect to %s", hostAddr),
				IsDefault:   i == 0,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hosts)
}

// HandleUserInfo returns information about the current authenticated user
func (h *Handler) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	id := identity.FromRequestCtx(r)

	if !id.Authenticated() {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userInfo := UserInfo{
		Username:      id.UserName(),
		Authenticated: id.Authenticated(),
		AuthTime:      id.AuthTime(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

// HandleWebInterface serves the main web interface
func (h *Handler) HandleWebInterface(w http.ResponseWriter, r *http.Request) {
	id := identity.FromRequestCtx(r)

	if !id.Authenticated() {
		// Redirect to authentication
		http.Redirect(w, r, "/connect", http.StatusFound)
		return
	}

	// Template data
	templateData := struct {
		Title               string
		Logo                string
		PageTitle           string
		SelectServerMessage string
		PreparingMessage    string
	}{
		Title:               h.webConfig.Branding.Title,
		Logo:                h.webConfig.Branding.Logo,
		PageTitle:           h.webConfig.Branding.PageTitle,
		SelectServerMessage: h.webConfig.Messages.SelectServer,
		PreparingMessage:    h.webConfig.Messages.Preparing,
	}

	w.Header().Set("Content-Type", "text/html")
	if err := h.htmlTemplate.Execute(w, templateData); err != nil {
		log.Printf("Failed to execute template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
