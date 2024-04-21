package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
	"github.com/bolkedebruin/rdpgw/cmd/auth/database"
	"github.com/bolkedebruin/rdpgw/cmd/auth/ntlm"
	"github.com/bolkedebruin/rdpgw/shared/auth"
	"github.com/msteinert/pam/v2"
	"github.com/thought-machine/go-flags"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"syscall"
)

const (
	protocol = "unix"
)

var opts struct {
	ServiceName string `short:"n" long:"name" default:"rdpgw" description:"the PAM service name to use"`
	SocketAddr  string `short:"s" long:"socket" default:"/tmp/rdpgw-auth.sock" description:"the location of the socket"`
	ConfigFile string `short:"c" long:"conf" default:"rdpgw-auth.yaml" description:"users config file for NTLM (yaml)"`
}

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

func (s *AuthServiceImpl) Authenticate(ctx context.Context, message *auth.UserPass) (*auth.AuthResponse, error) {
	t, err := pam.StartFunc(s.serviceName, message.Username, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return message.Password, nil
		case pam.PromptEchoOn, pam.ErrorMsg, pam.TextInfo:
			return "", nil
		}
		return "", errors.New("unrecognized PAM message style")
	})

	r := &auth.AuthResponse{}
	r.Authenticated = false

	if err != nil {
		log.Printf("Error authenticating user: %s due to: %s", message.Username, err)
		r.Error = err.Error()
		return r, err
	}
	defer func() {
		err := t.End()
		if err != nil {
			fmt.Fprintf(os.Stderr, "end: %v\n", err)
			os.Exit(1)
		}
	}()
	if err = t.Authenticate(0); err != nil {
		log.Printf("Authentication for user: %s failed due to: %s", message.Username, err)
		r.Error = err.Error()
		return r, nil
	}

	if err = t.AcctMgmt(0); err != nil {
		log.Printf("Account authorization for user: %s failed due to %s", message.Username, err)
		r.Error = err.Error()
		return r, nil
	}

	log.Printf("User: %s authenticated", message.Username)
	r.Authenticated = true
	return r, nil
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

func main() {
	_, err := flags.Parse(&opts)
	if err != nil {
		var fErr *flags.Error
		if errors.As(err, &fErr) {
			if fErr.Type == flags.ErrHelp {
				fmt.Printf("Acknowledgements:\n")
				fmt.Printf(" - This product includes software developed by the Thomson Reuters Global Resources. (go-ntlm - https://github.com/m7913d/go-ntlm - BSD-4 License)\n")
			}
		}
		return
	}

	conf = config.Load(opts.ConfigFile)

	log.Printf("Starting auth server on %s", opts.SocketAddr)
	cleanup := func() {
		if _, err := os.Stat(opts.SocketAddr); err == nil {
			if err := os.RemoveAll(opts.SocketAddr); err != nil {
				log.Fatal(err)
			}
		}
	}
	cleanup()

	oldUmask := syscall.Umask(0)
	listener, err := net.Listen(protocol, opts.SocketAddr)
	syscall.Umask(oldUmask)
	if err != nil {
		log.Fatal(err)
	}
	server := grpc.NewServer()
	db := database.NewConfig(conf.Users)
	service := NewAuthService(opts.ServiceName, db)
	auth.RegisterAuthenticateServer(server, service)
	server.Serve(listener)
}
