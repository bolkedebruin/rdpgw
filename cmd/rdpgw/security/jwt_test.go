package security

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"golang.org/x/oauth2"
)

func TestGenerateUserToken(t *testing.T) {
	cases := []struct {
		SigningKey    []byte
		EncryptionKey []byte
		name          string
		username      string
	}{
		{
			SigningKey:    []byte("5aa3a1568fe8421cd7e127d5ace28d2d"),
			EncryptionKey: []byte("d3ecd7e565e56e37e2f2e95b584d8c0c"),
			name:          "sign_and_encrypt",
			username:      "test_sign_and_encrypt",
		},
		{
			SigningKey:    nil,
			EncryptionKey: []byte("d3ecd7e565e56e37e2f2e95b584d8c0c"),
			name:          "encrypt_only",
			username:      "test_encrypt_only",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			SigningKey = tc.SigningKey
			UserEncryptionKey = tc.EncryptionKey
			token, err := GenerateUserToken(context.Background(), tc.username)
			if err != nil {
				t.Fatalf("GenerateUserToken failed: %s", err)
			}
			claims, err := UserInfo(context.Background(), token)
			if err != nil {
				t.Fatalf("UserInfo failed: %s", err)
			}
			if claims.Subject != tc.username {
				t.Fatalf("Expected %s, got %s", tc.username, claims.Subject)
			}
		})
	}

}

func TestPAACookie(t *testing.T) {
	SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")
	EncryptionKey = []byte("d3ecd7e565e56e37e2f2e95b584d8c0c")

	username := "test_paa_cookie"
	attr_client_ip := "127.0.0.1"
	attr_access_token := "aabbcc"

	id := identity.NewUser()
	id.SetUserName(username)
	id.SetAttribute(identity.AttrClientIp, attr_client_ip)
	id.SetAttribute(identity.AttrAccessToken, attr_access_token)

	ctx := context.Background()
	ctx = context.WithValue(ctx, identity.CTXKey, id)

	_, err := GeneratePAAToken(ctx, "test_paa_cookie", "host.does.not.exist")
	if err != nil {
		t.Fatalf("GeneratePAAToken failed: %s", err)
	}
	/*ok, err := CheckPAACookie(ctx, token)
	if err != nil {
		t.Fatalf("CheckPAACookie failed: %s", err)
	}
	if !ok {
		t.Fatalf("CheckPAACookie failed")
	}*/
}

// paaPayload returns the decoded JSON payload of a signed JWT (compact
// serialization: header.payload.signature). The PAA cookie is a JWS over
// HS256, so the payload is base64url-decodable plaintext.
func paaPayload(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWS compact (3 parts), got %d in %q", len(parts), token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return string(raw)
}

// TestPAACookieDoesNotEmbedAccessToken asserts that the PAA cookie does not
// carry the IdP access token in its payload. The access token is a bearer
// credential for other OIDC-protected resources; embedding it in a cookie
// that travels in the .rdp file (or any access log) leaks it well beyond
// the gateway.
func TestPAACookieDoesNotEmbedAccessToken(t *testing.T) {
	SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")

	const accessToken = "redacted-idp-access-token-1234567890abcdef"

	id := identity.NewUser()
	id.SetUserName("alice")
	id.SetAttribute(identity.AttrClientIp, "10.0.0.1")
	id.SetAttribute(identity.AttrAccessToken, accessToken)
	ctx := context.WithValue(context.Background(), identity.CTXKey, id)

	token, err := GeneratePAAToken(ctx, "alice", "rdp.example.com")
	if err != nil {
		t.Fatalf("GeneratePAAToken: %v", err)
	}
	payload := paaPayload(t, token)
	if strings.Contains(payload, accessToken) {
		t.Errorf("PAA cookie embeds the IdP access token in plaintext\npayload: %s", payload)
	}
}

// TestPAACookieHasAudienceClaim asserts that the PAA cookie declares its
// audience. Without `aud`, any JWS the rdpgw signing key produces (a future
// non-PAA token, a maintainer-tool token, ...) would be indistinguishable
// from a PAA cookie at the gateway endpoint.
func TestPAACookieHasAudienceClaim(t *testing.T) {
	SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")

	id := identity.NewUser()
	id.SetUserName("alice")
	id.SetAttribute(identity.AttrClientIp, "10.0.0.1")
	id.SetAttribute(identity.AttrAccessToken, "irrelevant")
	ctx := context.WithValue(context.Background(), identity.CTXKey, id)

	token, err := GeneratePAAToken(ctx, "alice", "rdp.example.com")
	if err != nil {
		t.Fatalf("GeneratePAAToken: %v", err)
	}
	payload := paaPayload(t, token)
	if !strings.Contains(payload, `"aud"`) {
		t.Errorf("PAA cookie has no aud claim\npayload: %s", payload)
	}
}

// TestCheckPAACookieIsSelfContained asserts that validating a PAA cookie
// does not require a live IdP. Today CheckPAACookie calls
// OIDCProvider.UserInfo with the embedded access token to look up the
// subject; both the network roundtrip and the dependency on a still-live
// access token are unnecessary because the gateway already signed Subject
// itself at issue time.
func TestCheckPAACookieIsSelfContained(t *testing.T) {
	SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")
	OIDCProvider = nil
	Oauth2Config = oauth2.Config{}
	VerifyClientIP = false

	issueId := identity.NewUser()
	issueId.SetUserName("alice")
	issueId.SetAttribute(identity.AttrClientIp, "10.0.0.1")
	issueId.SetAttribute(identity.AttrAccessToken, "irrelevant")
	issueCtx := context.WithValue(context.Background(), identity.CTXKey, issueId)

	token, err := GeneratePAAToken(issueCtx, "alice", "rdp.example.com")
	if err != nil {
		t.Fatalf("GeneratePAAToken: %v", err)
	}

	checkId := identity.NewUser()
	checkId.SetUserName("alice")
	checkId.SetAttribute(identity.AttrClientIp, "10.0.0.1")
	checkCtx := context.WithValue(context.Background(), identity.CTXKey, checkId)
	tun := &protocol.Tunnel{User: checkId}
	checkCtx = context.WithValue(checkCtx, protocol.CtxTunnel, tun)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("CheckPAACookie panicked without a live IdP (expected: trust the signed Subject): %v", r)
		}
	}()

	ok, err := CheckPAACookie(checkCtx, token)
	if err != nil {
		t.Errorf("CheckPAACookie returned error: %v", err)
	}
	if !ok {
		t.Errorf("CheckPAACookie returned ok=false for a valid cookie")
	}
	if tun.User.UserName() != "alice" {
		t.Errorf("tunnel.User = %q, want %q", tun.User.UserName(), "alice")
	}
}
