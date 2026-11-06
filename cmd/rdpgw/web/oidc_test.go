package web

import (
	"net/http/httptest"
	"testing"
)

func TestFindUserNameInClaims(t *testing.T) {
	cases := []struct {
		name    string
		claim   string
		data    map[string]interface{}
		ret     string
		wantErr bool
	}{
		{
			name: "preferred_username",
			data: map[string]interface{}{"preferred_username": "exists"},
			ret:  "exists",
		},
		{
			name: "upn",
			data: map[string]interface{}{"upn": "exists"},
			ret:  "exists",
		},
		{
			name: "unique_name",
			data: map[string]interface{}{"unique_name": "exists"},
			ret:  "exists",
		},
		{
			name: "username",
			data: map[string]interface{}{"username": "exists"},
			ret:  "exists",
		},
		{
			name: "default order",
			data: map[string]interface{}{"upn": "upn", "preferred_username": "preferred"},
			ret:  "preferred",
		},
		{
			name: "empty value is skipped",
			data: map[string]interface{}{"preferred_username": "", "upn": "upn"},
			ret:  "upn",
		},
		{
			name:    "no claim",
			data:    map[string]interface{}{"fail": "exists"},
			wantErr: true,
		},
		{
			name:    "email is not a default claim",
			data:    map[string]interface{}{"email": "user@example.com", "email_verified": true},
			wantErr: true,
		},
		{
			name:  "configured claim",
			claim: "email",
			data:  map[string]interface{}{"email": "user@example.com", "email_verified": true},
			ret:   "user@example.com",
		},
		{
			name:  "configured claim ignores defaults",
			claim: "email",
			data: map[string]interface{}{
				"preferred_username": "preferred",
				"email":              "user@example.com",
				"email_verified":     true,
			},
			ret: "user@example.com",
		},
		{
			name:    "configured claim missing",
			claim:   "email",
			data:    map[string]interface{}{"preferred_username": "preferred"},
			wantErr: true,
		},
		{
			name:  "email verified as string",
			claim: "email",
			data:  map[string]interface{}{"email": "user@example.com", "email_verified": "true"},
			ret:   "user@example.com",
		},
		{
			name:    "email not verified",
			claim:   "email",
			data:    map[string]interface{}{"email": "user@example.com", "email_verified": false},
			wantErr: true,
		},
		{
			name:    "email verification missing",
			claim:   "email",
			data:    map[string]interface{}{"email": "user@example.com"},
			wantErr: true,
		},
		{
			name:  "other configured claim",
			claim: "sAMAccountName",
			data:  map[string]interface{}{"sAMAccountName": "user", "preferred_username": "preferred"},
			ret:   "user",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := findUsernameInClaims(tc.data, tc.claim)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got username %q", s)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if s != tc.ret {
				t.Fatalf("expected return: %v, got: %v", tc.ret, s)
			}
		})
	}
}

func TestOIDCStateManagement(t *testing.T) {
	// Initialize session store for testing
	sessionKey := []byte("testsessionkeytestsessionkey1234")  // 32 bytes
	encryptionKey := []byte("testencryptionkeytestencrypt1234")  // 32 bytes
	InitStore(sessionKey, encryptionKey, "cookie", 8192)

	// Test storing and retrieving OIDC state
	t.Run("StoreAndRetrieveState", func(t *testing.T) {
		// Create test request and response
		req := httptest.NewRequest("GET", "/connect", nil)
		w := httptest.NewRecorder()

		state := "test-state-12345"
		redirectURL := "/original-request"

		// Store state
		err := storeOIDCState(w, req, state, redirectURL)
		if err != nil {
			t.Fatalf("Failed to store OIDC state: %v", err)
		}

		// Create a new request with the same session cookie
		callbackReq := httptest.NewRequest("GET", "/callback", nil)

		// Copy session cookie from response to new request
		for _, cookie := range w.Result().Cookies() {
			callbackReq.AddCookie(cookie)
		}

		// Retrieve state
		retrievedURL, found := getOIDCState(callbackReq, state)
		if !found {
			t.Fatal("Expected to find OIDC state, but it was not found")
		}

		if retrievedURL != redirectURL {
			t.Fatalf("Expected redirect URL '%s', got '%s'", redirectURL, retrievedURL)
		}
	})

	t.Run("StateNotFound", func(t *testing.T) {
		// Create test request
		req := httptest.NewRequest("GET", "/callback", nil)

		// Try to retrieve non-existent state
		_, found := getOIDCState(req, "non-existent-state")
		if found {
			t.Fatal("Expected state not to be found, but it was found")
		}
	})

	t.Run("EmptySession", func(t *testing.T) {
		// Create fresh request with no session
		req := httptest.NewRequest("GET", "/callback", nil)

		// Try to retrieve state from empty session
		_, found := getOIDCState(req, "any-state")
		if found {
			t.Fatal("Expected state not to be found in empty session, but it was found")
		}
	})
}
