package web

import (
        "encoding/base64"
        "errors"
        "fmt"
        "github.com/bolkedebruin/rdpgw/cmd/rdpgw/database"
        "github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
        "github.com/patrickmn/go-cache"
        "github.com/m7913d/go-ntlm/ntlm"
        "log"
        "net/http"
        "time"
)

const (
        cacheExpiration = time.Minute
        cleanupInterval = time.Minute * 5
)

type ntlmAuthMode uint32
const (
        authNone ntlmAuthMode = iota
        authNTLM
        authNegotiate
)

type NTLMAuthHandler struct {
        contextCache *cache.Cache
        
        // Information about the server, returned to the client during authentication
        ServerName string // e.g. EXAMPLE1
        DomainName string // e.g. EXAMPLE
        DnsServerName string // e.g. example1.example.com
        DnsDomainName string // e.g. example.com
        DnsTreeName string // e.g. example.com
        
        Database database.Database
}

func NewNTLMAuthHandler (database database.Database) (*NTLMAuthHandler) {
        return &NTLMAuthHandler{
                contextCache: cache.New(cacheExpiration, cleanupInterval),
                Database: database,
        }
}

func (h *NTLMAuthHandler) NTLMAuth(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
                //log.Printf("NTLM request")

                authPayload, authMode, err := h.getAuthPayload(r)
                if err != nil {
                        log.Printf("Failed parsing auth header: %s", err)
                        w.Header().Add("WWW-Authenticate", `NTLM,Basic realm="restricted", charset="UTF-8"`)
                        http.Error(w, "Unauthorized", http.StatusUnauthorized)
                        return
                }

                c := h.getContext(r)
                if c.Auth(w, authPayload, authMode) {
                        username := c.GetUsername()
                        log.Printf("NTLM: User %s authenticated", username)
                        id := identity.FromRequestCtx(r)
                        id.SetUserName(username)
                        id.SetAuthenticated(true)
                        id.SetAuthTime(time.Now())
                        next.ServeHTTP(w, identity.AddToRequestCtx(id, r))
                }
        }
}

func (h *NTLMAuthHandler) getAuthPayload (r *http.Request) (payload string, authMode ntlmAuthMode, err error) {
        authorisationEncoded := r.Header.Get("Authorization")
        if authorisationEncoded[0:5] == "NTLM " {
                return authorisationEncoded[5:], authNTLM, nil
        }
        if authorisationEncoded[0:10] == "Negotiate " {
                return authorisationEncoded[10:], authNegotiate, nil
        }
        return "", authNone, errors.New(fmt.Sprintf("Invalid NTLM Authorisation header: %s", authorisationEncoded))
}

func (h *NTLMAuthHandler) getContext (r *http.Request) (*ntlmContext) {
        if c_, found := h.contextCache.Get(r.RemoteAddr); found {
                if c, ok := c_.(*ntlmContext); ok {
                        return c
                }
        }
        c := new(ntlmContext)
        c.h = h
        h.contextCache.Set(r.RemoteAddr, c, cache.DefaultExpiration)
        return c
}

type ntlmContext struct {
        session ntlm.ServerSession
        h *NTLMAuthHandler
}

func (c *ntlmContext) GetUsername () (username string) {
        username, _, _ = c.session.GetUserInfo()
        return username
}

func (c *ntlmContext) Auth(w http.ResponseWriter, authorisationEncoded string, authMode ntlmAuthMode) (succeeded bool) {
        authorisation, err := base64.StdEncoding.DecodeString(authorisationEncoded)
        if err != nil {
                log.Printf("Failed to decode NTLM Authorisation header: %s due to: %s", authorisationEncoded, err)
                http.Error(w, "Server error", http.StatusInternalServerError)
                return false
        }

        nm, err := ntlm.ParseNegotiateMessage(authorisation)
        if err == nil {
                c.negotiate(w, nm, authMode)
                return false
        }
        if (nm != nil && nm.MessageType == 1) {
                log.Printf("Failed to parse NTLM Authorisation header: %s due to %s", authorisationEncoded, err)
                http.Error(w, "Server error", http.StatusInternalServerError)
                return false
        } else if c.session == nil {
                log.Printf("New NTLM auth sequence should start with negotioate request: %s", authorisationEncoded)
                http.Error(w, "Server error", http.StatusInternalServerError)
                return false
        }

        am, err := ntlm.ParseAuthenticateMessage(authorisation, 2)
        if err == nil {
                return c.authenticate(w, am)
        }

        log.Printf("Failed to parse NTLM Authorisation header: %s due to %s", authorisationEncoded, err)
        http.Error(w, "Server error", http.StatusInternalServerError)
        return false
}

func (c *ntlmContext) getAuthPrefix (authMode ntlmAuthMode) (prefix string) {
        if authMode == authNTLM {
                return "NTLM "
        }
        if authMode == authNegotiate {
                return "Negotiate "
        }
        return ""
}

func (c *ntlmContext) requestAuthenticate (w http.ResponseWriter) {
        w.Header().Add("WWW-Authenticate", `NTLM,Basic realm="restricted", charset="UTF-8"`)
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func (c *ntlmContext) negotiate(w http.ResponseWriter, nm *ntlm.NegotiateMessage, authMode ntlmAuthMode) {
        //log.Printf("NTLM negotiate request: %v", nm)

        session, err := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionOrientedMode)

        if err != nil {
                c.session = nil;
                log.Printf("Failed to create NTLM server session: %s", err)
                http.Error(w, "Server error", http.StatusInternalServerError)
                return
        }

        c.session = session
        c.session.SetDomainName(c.h.DomainName)
        c.session.SetComputerName(c.h.ServerName)
        c.session.SetDnsDomainName(c.h.DnsDomainName)
        c.session.SetDnsComputerName(c.h.DnsServerName)
        c.session.SetDnsTreeName(c.h.DnsTreeName)

        err = c.session.ProcessNegotiateMessage(nm)
        if err != nil {
                log.Printf("Failed to process NTLM negotiate message: %s", err)
                http.Error(w, "Server error", http.StatusInternalServerError)
                return
        }

        cm, err := c.session.GenerateChallengeMessage()
        if err != nil {
                log.Printf("Failed to generate NTLM challenge message: %s", err)
                http.Error(w, "Server error", http.StatusInternalServerError)
                return
        }

        log.Printf("Sending NTLM challenge request")
        //log.Printf("Sending NTLM challenge request: %v", cm)

        cmBytes := cm.Bytes()
        w.Header().Add("WWW-Authenticate", c.getAuthPrefix(authMode)+base64.StdEncoding.EncodeToString(cmBytes))
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func (c *ntlmContext) authenticate(w http.ResponseWriter, am *ntlm.AuthenticateMessage) (succeeded bool) {
        //log.Printf("NTLM Authenticate request: %v", am)
        
        if c.session == nil {
                log.Printf("NTLM Authenticate requires active session: first call negotioate")
                http.Error(w, "Server error", http.StatusInternalServerError)
                return false
        }
        
        username := am.UserName.String()
        password := c.h.Database.GetPassword (username)
        if password == "" {
                log.Printf("NTLM: unknown username specified: %s", username)
                c.requestAuthenticate(w)
                return false
        }
        
        c.session.SetUserInfo(username,password,"")

        err := c.session.ProcessAuthenticateMessage(am)
        if err != nil {
                log.Printf("Failed to process NTLM authenticate message: %s", err)
                c.requestAuthenticate(w)
                return false
        }

        return true
}
