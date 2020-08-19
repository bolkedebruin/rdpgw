package security

import (
	"context"
	"errors"
	"fmt"
	"github.com/bolkedebruin/rdpgw/common"
	"github.com/bolkedebruin/rdpgw/protocol"
	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
	"log"
	"time"
)

var (
	SigningKey        []byte
	EncryptionKey     []byte
	UserSigningKey    []byte
	UserEncryptionKey []byte
)

var ExpiryTime time.Duration = 5

type customClaims struct {
	RemoteServer string `json:"remoteServer"`
	ClientIP     string `json:"clientIp"`
	AccessToken  string `json:"accessToken"`
}

func VerifyPAAToken(ctx context.Context, tokenString string) (bool, error) {
	token, err := jwt.ParseSigned(tokenString)

	// check if the signing algo matches what we expect
	for _, header := range token.Headers {
		if header.Algorithm != string(jose.HS256) {
			return false, fmt.Errorf("unexpected signing method: %v", header.Algorithm)
		}
	}

	standard := jwt.Claims{}
	custom := customClaims{}

	// Claims automagically checks the signature...
	err = token.Claims(SigningKey, &standard, &custom)
	if err != nil {
		log.Printf("token signature validation failed due to %s", err)
		return false, err
	}

	// ...but doesn't check the expiry claim :/
	err = standard.Validate(jwt.Expected{
		Issuer: "rdpgw",
		Time:   time.Now(),
	})

	if err != nil {
		log.Printf("token validation failed due to %s", err)
		return false, err
	}

	s := getSessionInfo(ctx)

	s.RemoteServer = custom.RemoteServer
	s.ClientIp = custom.ClientIP

	return true, nil
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

	/*if s.ClientIp != common.GetClientIp(ctx) {
		log.Printf("Current client ip address %s does not match token client ip %s",
			common.GetClientIp(ctx), s.ClientIp)
		return false, nil
	}*/

	return true, nil
}

func GeneratePAAToken(ctx context.Context, username string, server string) (string, error) {
	if len(SigningKey) < 32 {
		return "", errors.New("token signing key not long enough or not specified")
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: SigningKey}, nil)
	if err != nil {
		log.Printf("Cannot obtain signer %s", err)
		return "", err
	}

	standard := jwt.Claims{
		Issuer:  "rdpgw",
		Expiry:  jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
		Subject: username,
	}

	private := customClaims{
		RemoteServer: server,
		ClientIP:     common.GetClientIp(ctx),
		AccessToken:  common.GetAccessToken(ctx),
	}

	if token, err := jwt.Signed(sig).Claims(standard).Claims(private).CompactSerialize(); err != nil {
		log.Printf("Cannot sign PAA token %s", err)
		return "", err
	} else {
		return token, nil
	}
}

func GenerateUserToken(ctx context.Context, userName string) (string, error) {
	if len(UserEncryptionKey) < 32 {
		return "", errors.New("user token encryption key not long enough or not specified")
	}

	claims := jwt.Claims{
		Subject: userName,
		Expiry:  jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
		Issuer:  "rdpgw",
	}

	enc, err := jose.NewEncrypter(
		jose.A128CBC_HS256,
		jose.Recipient{Algorithm: jose.DIRECT, Key: UserEncryptionKey},
		(&jose.EncrypterOptions{Compression: jose.DEFLATE}).WithContentType("JWT"),
	)

	if err != nil {
		log.Printf("Cannot encrypt user token due to %s", err)
		return "", err
	}

	// this makes the token bigger and we deal with a limited space of 511 characters
	// sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: SigningKey}, nil)
	// token, err := jwt.SignedAndEncrypted(sig, enc).Claims(claims).CompactSerialize()
	token, err := jwt.Encrypted(enc).Claims(claims).CompactSerialize()
	return token, err
}

func getSessionInfo(ctx context.Context) *protocol.SessionInfo {
	s, ok := ctx.Value("SessionInfo").(*protocol.SessionInfo)
	if !ok {
		log.Printf("cannot get session info from context")
		return nil
	}
	return s
}
