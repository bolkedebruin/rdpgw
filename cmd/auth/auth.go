package main

import (
	"errors"
	"github.com/golang/protobuf/proto"
	ipc "github.com/james-barrow/golang-ipc"
	"github.com/msteinert/pam"
	"github.com/thought-machine/go-flags"
	"log"
)

var opts struct {
	serviceName string `short:"s" long:"service" default:"rdpgw" description:"the PAM service name to use"`
}

func auth(service, user, passwd string) error {
	t, err := pam.StartFunc(service, user, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return passwd, nil
		case pam.PromptEchoOn, pam.ErrorMsg, pam.TextInfo:
			return "", nil
		}
		return "", errors.New("unrecognized PAM message style")
	})

	if err != nil {
		return err
	}

	if err = t.Authenticate(0); err != nil {
		return err
	}

	return nil
}

func main() {
	_, err := flags.Parse(&opts)
	if err != nil {
		panic(err)
	}

	config := &ipc.ServerConfig{UnmaskPermissions: true}
	sc, err := ipc.StartServer("rdpgw-auth", config)
	for {
		msg, err := sc.Read()
		if err != nil {
			log.Printf("server error, %s", err)
			continue
		}
		if msg.MsgType > 0 {
			req := &UserPass{}
			if err = proto.Unmarshal(msg.Data, req); err != nil {
				log.Printf("cannot unmarshal request %s", string(msg.Data))
				continue
			}
			err := auth(opts.serviceName, req.Username, req.Password)
			if err != nil {
				res := &Response{Status: "cannot authenticate"}
				out, err := proto.Marshal(res)
				if err != nil {
					log.Fatalf("cannot marshal response due to %s", err)
				}
				sc.Write(1, out)
			}
		}
	}
	if err != nil {
		log.Printf("cannot authenticate due to %s", err)
	}
}
