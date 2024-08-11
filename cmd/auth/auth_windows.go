// +build windows

package main

import (
	"errors"
	"fmt"
	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
	"github.com/bolkedebruin/rdpgw/cmd/auth/database"
	"github.com/bolkedebruin/rdpgw/shared/auth"
	"github.com/thought-machine/go-flags"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
)

const (
        protocol = "tcp"
)

var opts struct {
        ServiceName string `short:"n" long:"name" default:"rdpgw" description:"the PAM service name to use"`
        SocketAddr  string `short:"s" long:"socket" default:"127.0.0.1:3000" description:"the location of the socket"`
        ConfigFile string `short:"c" long:"conf" default:"rdpgw-auth.yaml" description:"users config file for NTLM (yaml)"`
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

	listener, err := net.Listen(protocol, opts.SocketAddr)
	if err != nil {
		log.Fatal(err)
	}
	server := grpc.NewServer()
	db := database.NewConfig(conf.Users)
	service := NewAuthService(opts.ServiceName, db)
	auth.RegisterAuthenticateServer(server, service)
	server.Serve(listener)
}
