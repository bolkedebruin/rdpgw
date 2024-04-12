package security

import (
	"context"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"testing"
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
