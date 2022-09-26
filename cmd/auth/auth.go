package main

import (
	"context"
	"errors"
	"github.com/bolkedebruin/rdpgw/shared/auth"
	"github.com/msteinert/pam"
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
}

type AuthServiceImpl struct {
	serviceName string
}

var _ auth.AuthenticateServer = (*AuthServiceImpl)(nil)

func NewAuthService(serviceName string) auth.AuthenticateServer {
	s := &AuthServiceImpl{serviceName: serviceName}
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

func main() {
	_, err := flags.Parse(&opts)
	if err != nil {
		panic(err)
	}

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
	service := NewAuthService(opts.ServiceName)
	auth.RegisterAuthenticateServer(server, service)
	server.Serve(listener)
}
