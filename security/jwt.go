package security

import (
	"errors"
	"fmt"
	"github.com/bolkedebruin/rdpgw/protocol"
	"github.com/dgrijalva/jwt-go/v4"
	"log"
	"time"
)

var SigningKey []byte
var ExpiryTime time.Duration = 5

type customClaims struct {
	RemoteServer string `json:"remoteServer"`
	jwt.StandardClaims
}

func VerifyPAAToken(s *protocol.SessionInfo, tokenString string) (bool, error) {
	token, err := jwt.ParseWithClaims(tokenString, &customClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return SigningKey, nil
	})

	if err != nil {
		return false, err
	}

	if _, ok := token.Claims.(*customClaims); ok && token.Valid {
		return true, nil
	}

	log.Printf("token validation failed: %s", err)
	return false, err
}

func GeneratePAAToken(username string, server string) (string, error) {
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
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: exp,
			IssuedAt: now,
			Issuer: "rdpgw",
			Subject: username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	if ss, err := token.SignedString(SigningKey); err != nil {
		log.Printf("Cannot sign PAA token %s", err)
		return "", err
	} else {
		return ss, nil
	}
}