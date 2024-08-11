package main

import (
	"context"
	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
	"github.com/bolkedebruin/rdpgw/cmd/auth/database"
	"github.com/bolkedebruin/rdpgw/cmd/auth/ntlm"
	"github.com/bolkedebruin/rdpgw/shared/auth"
	"log"
)

type AuthServiceImpl struct {
	auth.UnimplementedAuthenticateServer

	serviceName string
	ntlm *ntlm.NTLMAuth
}

var conf config.Configuration
var _ auth.AuthenticateServer = (*AuthServiceImpl)(nil)

func NewAuthService(serviceName string, database database.Database) auth.AuthenticateServer {
	s := &AuthServiceImpl{
		serviceName: serviceName,
		ntlm: ntlm.NewNTLMAuth(database),
	}
	return s
}

func (s *AuthServiceImpl) NTLM(ctx context.Context, message *auth.NtlmRequest) (*auth.NtlmResponse, error) {
	r, err := s.ntlm.Authenticate(message)

	if err != nil {
		log.Printf("[%s] NTLM failed: %s", message.Session, err)
	} else if r.Authenticated {
		log.Printf("[%s] User: %s authenticated using NTLM", message.Session, r.Username)
	} else if r.NtlmMessage != "" {
		log.Printf("[%s] Sending NTLM challenge", message.Session)
	}

	return r, err
}
