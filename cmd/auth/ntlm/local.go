package ntlm

import (
	"fmt"
	"log"

	"github.com/bolkedebruin/rdpgw/cmd/auth/database"
	"github.com/m7913d/go-ntlm/ntlm"
)

// LocalBackend verifies NTLMv2 responses in-process against passwords
// retrieved from a Database (typically the users listed in the
// configuration file).
type LocalBackend struct {
	// Information about the server, returned to the client during authentication
	ServerName    string // e.g. EXAMPLE1
	DomainName    string // e.g. EXAMPLE
	DnsServerName string // e.g. example1.example.com
	DnsDomainName string // e.g. example.com
	DnsTreeName   string // e.g. example.com

	Database database.Database
}

func NewLocalBackend(database database.Database) *LocalBackend {
	return &LocalBackend{Database: database}
}

func (b *LocalBackend) NewContext() Context {
	return &localContext{b: b}
}

type localContext struct {
	b       *LocalBackend
	session ntlm.ServerSession
}

func (c *localContext) Negotiate(negotiate []byte) ([]byte, error) {
	nm, err := ntlm.ParseNegotiateMessage(negotiate)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse NTLM negotiate message: %s", err)
	}

	session, err := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionOrientedMode)
	if err != nil {
		c.session = nil
		return nil, fmt.Errorf("Failed to create NTLM server session: %s", err)
	}

	c.session = session
	c.session.SetRequireNtHash(true)
	c.session.SetDomainName(c.b.DomainName)
	c.session.SetComputerName(c.b.ServerName)
	c.session.SetDnsDomainName(c.b.DnsDomainName)
	c.session.SetDnsComputerName(c.b.DnsServerName)
	c.session.SetDnsTreeName(c.b.DnsTreeName)

	if err = c.session.ProcessNegotiateMessage(nm); err != nil {
		return nil, fmt.Errorf("Failed to process NTLM negotiate message: %s", err)
	}

	cm, err := c.session.GenerateChallengeMessage()
	if err != nil {
		return nil, fmt.Errorf("Failed to generate NTLM challenge message: %s", err)
	}
	return cm.Bytes(), nil
}

func (c *localContext) Authenticate(authenticate []byte) (string, bool, error) {
	if c.session == nil {
		return "", false, fmt.Errorf("NTLM Authenticate requires active session: first call negotiate")
	}

	am, err := ntlm.ParseAuthenticateMessage(authenticate, 2)
	if err != nil {
		return "", false, fmt.Errorf("Failed to parse NTLM authenticate message: %s", err)
	}

	username := am.UserName.String()
	password := c.b.Database.GetPassword(username)
	if password == "" {
		log.Printf("NTLM: unknown username specified: %s", username)
		return "", false, nil
	}

	c.session.SetUserInfo(username, password, "")

	if err := c.session.ProcessAuthenticateMessage(am); err != nil {
		log.Printf("Failed to process NTLM authenticate message: %s", err)
		return "", false, nil
	}

	return username, true, nil
}

func (c *localContext) Close() {
	c.session = nil
}
