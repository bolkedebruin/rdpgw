package security

import (
	"context"
	"errors"
	"fmt"
	"github.com/bolkedebruin/rdpgw/client"
	"github.com/bolkedebruin/rdpgw/protocol"
	"github.com/dgrijalva/jwt-go/v4"
	"log"
	"time"
)

var SigningKey []byte
var ExpiryTime time.Duration = 5

type customClaims struct {
	RemoteServer string `json:"remoteServer"`
	ClientIP	 string `json:"clientIp"`
	jwt.StandardClaims
}

func VerifyPAAToken(ctx context.Context, tokenString string) (bool, error) {
	token, err := jwt.ParseWithClaims(tokenString, &customClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return SigningKey, nil
	})

	if err != nil {
		return false, err
	}

	if c, ok := token.Claims.(*customClaims); ok && token.Valid {
		s := getSessionInfo(ctx)
		s.RemoteServer = c.RemoteServer
		s.ClientIp = c.ClientIP
		return true, nil
	}

	log.Printf("token validation failed: %s", err)
	return false, err
}

func VerifyServerFunc(ctx context.Context, host string) (bool, error) {
	s := getSessionInfo(ctx)
	if s == nil {
		return false, errors.New("no valid session info found in context")
	}

	if s.RemoteServer != host {
		log.Printf("Client specified host %s does not match token host %s", host, s.RemoteServer)
		return false, nil
	}

	if s.ClientIp != client.GetClientIp(ctx) {
		log.Printf("Current client ip address %s does not match token client ip %s",
			client.GetClientIp(ctx), s.ClientIp)
		return false, nil
	}

	return true, nil
}

func GeneratePAAToken(ctx context.Context, username string, server string) (string, error) {
	if len(SigningKey) < 32 {
		return "", errors.New("token signing key not long enough or not specified")
	}

	exp := &jwt.Time{
		Time: time.Now().Add(time.Minute * 5),
	}
	now := &jwt.Time{
		Time: time.Now(),
	}

	c := customClaims{
		RemoteServer: server,
		ClientIP: client.GetClientIp(ctx),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: exp,
			IssuedAt: now,
			Issuer: "rdpgw",
			Subject: username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	if ss, err := token.SignedString(SigningKey); err != nil {
		log.Printf("Cannot sign PAA token %s", err)
		return "", err
	} else {
		return ss, nil
	}
}

func getSessionInfo(ctx context.Context) *protocol.SessionInfo {
	s, ok := ctx.Value("SessionInfo").(*protocol.SessionInfo)
	if !ok {
		log.Printf("cannot get session info from context")
		return nil
	}
	return s
}