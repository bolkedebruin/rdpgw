package security

import (
	"context"
	"errors"
	"fmt"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/common"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
	"golang.org/x/oauth2"
	"log"
	"time"
)

var (
	SigningKey        []byte
	EncryptionKey     []byte
	UserSigningKey    []byte
	UserEncryptionKey []byte
	OIDCProvider	  *oidc.Provider
	Oauth2Config	  oauth2.Config
)

var ExpiryTime time.Duration = 5
var VerifyClientIP bool = true

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

	// validate the access token
	tokenSource := Oauth2Config.TokenSource(ctx, &oauth2.Token{AccessToken: custom.AccessToken})
	_, err = OIDCProvider.UserInfo(ctx, tokenSource)
	if err != nil {
		log.Printf("Cannot get user info for access token: %s", err)
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

	if VerifyClientIP && s.ClientIp != common.GetClientIp(ctx) {
		log.Printf("Current client ip address %s does not match token client ip %s",
			common.GetClientIp(ctx), s.ClientIp)
		return false, nil
	}

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

func UserInfo(ctx context.Context, token string) (jwt.Claims, error) {
	standard := jwt.Claims{}
	if len(UserEncryptionKey) > 0 && len(UserSigningKey) > 0 {
		enc, err := jwt.ParseSignedAndEncrypted(token)
		if err != nil {
			log.Printf("Cannot get token %s", err)
			return standard, errors.New("cannot get token")
		}
		token, err := enc.Decrypt(UserEncryptionKey)
		if err != nil {
			log.Printf("Cannot decrypt token %s", err)
			return standard, errors.New("cannot decrypt token")
		}
		if _, err := verifyAlg(token.Headers, string(jose.HS256)); err != nil {
			log.Printf("signature validation failure: %s", err)
			return standard, errors.New("signature validation failure")
		}
		if err = token.Claims(UserSigningKey, &standard); err != nil {
			log.Printf("cannot verify signature %s", err)
			return standard, errors.New("cannot verify signature")
		}
	} else if len(UserSigningKey) == 0 {
		token, err := jwt.ParseEncrypted(token)
		if err != nil {
			log.Printf("Cannot get token %s", err)
			return standard, errors.New("cannot get token")
		}
		err = token.Claims(UserEncryptionKey, &standard)
		if err != nil {
			log.Printf("Cannot decrypt token %s", err)
			return standard, errors.New("cannot decrypt token")
		}
	} else {
		token, err := jwt.ParseSigned(token)
		if err != nil {
			log.Printf("Cannot get token %s", err)
			return standard, errors.New("cannot get token")
		}
		if _, err := verifyAlg(token.Headers, string(jose.HS256)); err != nil {
			log.Printf("signature validation failure: %s", err)
			return standard, errors.New("signature validation failure")
		}
		err = token.Claims(UserSigningKey, &standard)
		if err = token.Claims(UserSigningKey, &standard); err != nil {
			log.Printf("cannot verify signature %s", err)
			return standard, errors.New("cannot verify signature")
		}
	}

	// go-jose doesnt verify the expiry
	err := standard.Validate(jwt.Expected{
		Issuer: "rdpgw",
		Time: time.Now(),
	})

	if err != nil {
		log.Printf("token validation failed due to %s", err)
		return standard, fmt.Errorf("token validation failed due to %s", err)
	}

	return standard, nil
}

func getSessionInfo(ctx context.Context) *protocol.SessionInfo {
	s, ok := ctx.Value("SessionInfo").(*protocol.SessionInfo)
	if !ok {
		log.Printf("cannot get session info from context")
		return nil
	}
	return s
}

func verifyAlg(headers []jose.Header, alg string) (bool, error) {
	for _, header := range headers {
		if header.Algorithm != alg {
			return false, fmt.Errorf("invalid signing method %s", header.Algorithm)
		}
	}
	return true, nil
}