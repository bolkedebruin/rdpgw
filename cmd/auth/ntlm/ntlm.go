package ntlm

import (
        "encoding/base64"
        "errors"
	"github.com/bolkedebruin/rdpgw/cmd/auth/database"
	"github.com/bolkedebruin/rdpgw/shared/auth"
        "github.com/patrickmn/go-cache"
        "github.com/m7913d/go-ntlm/ntlm"
	"fmt"
	"log"
        "time"
)

const (
        cacheExpiration = time.Minute
        cleanupInterval = time.Minute * 5
)

type NTLMAuth struct {
        contextCache *cache.Cache
        
        // Information about the server, returned to the client during authentication
        ServerName string // e.g. EXAMPLE1
        DomainName string // e.g. EXAMPLE
        DnsServerName string // e.g. example1.example.com
        DnsDomainName string // e.g. example.com
        DnsTreeName string // e.g. example.com
        
        Database database.Database
}

func NewNTLMAuth (database database.Database) (*NTLMAuth) {
	return &NTLMAuth{
                contextCache: cache.New(cacheExpiration, cleanupInterval),
                Database: database,
        }
}

func (h *NTLMAuth) Authenticate(message *auth.NtlmRequest) (*auth.NtlmResponse, error) {
	r := &auth.NtlmResponse{}
	r.Authenticated = false

	if message.Session == "" {
		return r, errors.New("Invalid (empty) session specified")
	}

	if message.NtlmMessage == "" {
		return r, errors.New("Empty NTLM message specified")
	}

	c := h.getContext(message.Session)
	err := c.Authenticate(message.NtlmMessage, r)

	if err != nil || r.Authenticated {
		h.removeContext(message.Session)
	}

	return r, err
}

func (h *NTLMAuth) getContext (session string) (*ntlmContext) {
	if c_, found := h.contextCache.Get(session); found {
                if c, ok := c_.(*ntlmContext); ok {
                        return c
                }
        }
        c := new(ntlmContext)
        c.h = h
	h.contextCache.Set(session, c, cache.DefaultExpiration)
        return c
}

func (h *NTLMAuth) removeContext (session string) {
	h.contextCache.Delete(session)
}

type ntlmContext struct {
        session ntlm.ServerSession
	h *NTLMAuth
}

func (c *ntlmContext) Authenticate(authorisationEncoded string, r *auth.NtlmResponse) (error) {
        authorisation, err := base64.StdEncoding.DecodeString(authorisationEncoded)
        if err != nil {
		return errors.New(fmt.Sprintf("Failed to decode NTLM Authorisation header: %s", err))
        }

        nm, err := ntlm.ParseNegotiateMessage(authorisation)
        if err == nil {
		return c.negotiate(nm, r)
        }
        if (nm != nil && nm.MessageType == 1) {
		return errors.New(fmt.Sprintf("Failed to parse NTLM Authorisation header: %s", err))
        } else if c.session == nil {
		return errors.New(fmt.Sprintf("New NTLM auth sequence should start with negotioate request"))
        }

        am, err := ntlm.ParseAuthenticateMessage(authorisation, 2)
        if err == nil {
		return c.authenticate(am, r)
        }

	return errors.New(fmt.Sprintf("Failed to parse NTLM Authorisation header: %s", err))
}

func (c *ntlmContext) negotiate(nm *ntlm.NegotiateMessage, r *auth.NtlmResponse) (error) {
        session, err := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionOrientedMode)

        if err != nil {
                c.session = nil;
		return errors.New(fmt.Sprintf("Failed to create NTLM server session: %s", err))
        }

        c.session = session
	c.session.SetRequireNtHash(true)
        c.session.SetDomainName(c.h.DomainName)
        c.session.SetComputerName(c.h.ServerName)
        c.session.SetDnsDomainName(c.h.DnsDomainName)
        c.session.SetDnsComputerName(c.h.DnsServerName)
        c.session.SetDnsTreeName(c.h.DnsTreeName)

        err = c.session.ProcessNegotiateMessage(nm)
        if err != nil {
		return errors.New(fmt.Sprintf("Failed to process NTLM negotiate message: %s", err))
        }

        cm, err := c.session.GenerateChallengeMessage()
        if err != nil {
		return errors.New(fmt.Sprintf("Failed to generate NTLM challenge message: %s", err))
	}

	r.NtlmMessage = base64.StdEncoding.EncodeToString(cm.Bytes())
	return nil
}

func (c *ntlmContext) authenticate(am *ntlm.AuthenticateMessage, r *auth.NtlmResponse) (error) {
        if c.session == nil {
		return errors.New(fmt.Sprintf("NTLM Authenticate requires active session: first call negotioate"))
        }
        
        username := am.UserName.String()
        password := c.h.Database.GetPassword (username)
        if password == "" {
		log.Printf("NTLM: unknown username specified: %s", username)
		return nil
        }
        
        c.session.SetUserInfo(username,password,"")

        err := c.session.ProcessAuthenticateMessage(am)
        if err != nil {
		log.Printf("Failed to process NTLM authenticate message: %s", err)
		return nil
        }

	r.Authenticated = true
	r.Username = username
	return nil
}
