package ntlm

import (
	"encoding/base64"
	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
	"github.com/bolkedebruin/rdpgw/cmd/auth/database"
	"github.com/bolkedebruin/rdpgw/shared/auth"
	"github.com/m7913d/go-ntlm/ntlm"
	"testing"
	"log"
)

func createTestDatabase () (database.Database) {
	user := config.UserConfig{}
	user.Username = "my_username"
	user.Password = "my_password"

	var users = []config.UserConfig{}
	users = append(users, user)

	config := database.NewConfig(users)

	return config
}

func TestNtlmValidCredentials(t *testing.T) {
	client := ntlm.V2ClientSession{}
	client.SetUserInfo("my_username", "my_password", "")

	authenticateResponse := authenticate(t, &client)
	if !authenticateResponse.Authenticated {
		t.Errorf("Failed to authenticate")
		return
	}
	if authenticateResponse.Username != "my_username" {
		t.Errorf("Wrong username returned")
		return
	}
}

func TestNtlmInvalidPassword(t *testing.T) {
	client := ntlm.V2ClientSession{}
	client.SetUserInfo("my_username", "my_invalid_password", "")

	authenticateResponse := authenticate(t, &client)
	if authenticateResponse.Authenticated {
		t.Errorf("Authenticated with wrong password")
		return
	}
	if authenticateResponse.Username != "" {
		t.Errorf("If authentication failed, no username should be returned")
		return
	}
}

func TestNtlmInvalidUsername(t *testing.T) {
	client := ntlm.V2ClientSession{}
	client.SetUserInfo("my_invalid_username", "my_password", "")

	authenticateResponse := authenticate(t, &client)
	if authenticateResponse.Authenticated {
		t.Errorf("Authenticated with wrong password")
		return
	}
	if authenticateResponse.Username != "" {
		t.Errorf("If authentication failed, no username should be returned")
		return
	}
}

func authenticate(t *testing.T, client *ntlm.V2ClientSession) (*auth.NtlmResponse) {
	session := "X"
	database := createTestDatabase()

	server := NewNTLMAuth(database)

	negotiate, err := client.GenerateNegotiateMessage()
	if err != nil {
		t.Errorf("Could not generate negotiate message: %s", err)
		return nil
	}

	negotiateRequest := &auth.NtlmRequest{}
	negotiateRequest.Session = session
	negotiateRequest.NtlmMessage = base64.StdEncoding.EncodeToString(negotiate.Bytes())
	negotiateResponse, err := server.Authenticate(negotiateRequest)
	if err != nil {
		t.Errorf("Could not generate challenge message: %s", err)
		return nil
	}
	if negotiateResponse.Authenticated {
		t.Errorf("User should not be authenticated by after negotiate message")
		return nil
	}
	if negotiateResponse.NtlmMessage == "" {
		t.Errorf("Could not generate challenge message")
		return nil
	}

	decodedChallenge, err := base64.StdEncoding.DecodeString(negotiateResponse.NtlmMessage)
	if err != nil {
		t.Errorf("Challenge should be base64 encoded: %s", err)
		return nil
	}

	challenge, err := ntlm.ParseChallengeMessage(decodedChallenge)
	if err != nil {
		t.Errorf("Invalid challenge message generated: %s", err)
		return nil
	}

	client.ProcessChallengeMessage(challenge)
	authenticate, err := client.GenerateAuthenticateMessage()
	if err != nil {
		t.Errorf("Could not generate authenticate message: %s", err)
		return nil
	}

	authenticateRequest := &auth.NtlmRequest{}
	authenticateRequest.Session = session
	authenticateRequest.NtlmMessage = base64.StdEncoding.EncodeToString(authenticate.Bytes())
	authenticateResponse, err := server.Authenticate(authenticateRequest)
	if err != nil {
		t.Errorf("Could not parse authenticate message: %s", err)
		return authenticateResponse
	}
	if authenticateResponse.NtlmMessage != "" {
		t.Errorf("Authenticate request should not generate a new NTLM message")
		return authenticateResponse
	}
	return authenticateResponse
}

func TestInvalidBase64 (t *testing.T) {
	testInvalidDataBase(t, "X", "X") // not valid base64
}

func TestInvalidData (t *testing.T) {
	testInvalidDataBase(t, "X", "XXXX") // valid base64
}

func TestInvalidDataEmptyMessage (t *testing.T) {
	testInvalidDataBase(t, "X", "")
}

func TestEmptySession (t *testing.T) {
	testInvalidDataBase(t, "", "XXXX")
}

func testInvalidDataBase (t *testing.T, session string, data string) {
	database := createTestDatabase()
	server := NewNTLMAuth(database)

	request := &auth.NtlmRequest{}
	request.Session = session
	request.NtlmMessage = data
	response, err := server.Authenticate(request)
	log.Printf("%s",err)
	if err == nil {
		t.Errorf("Invalid request should return an error")
	}
	if response.Authenticated {
		t.Errorf("User should not be authenticated using invalid data")
	}
	if response.NtlmMessage != "" {
		t.Errorf("No NTLM message should be generated for invalid data")
	}
}
