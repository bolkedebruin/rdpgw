package web

import (
	"net/http/httptest"
	"testing"
)

func TestFindUserNameInClaims(t *testing.T) {
	cases := []struct {
		data map[string]interface{}
		ret  string
		name string
	}{
		{
			data: map[string]interface{}{
				"preferred_username": "exists",
			},
			ret:  "exists",
			name: "preferred_username",
		},
		{
			data: map[string]interface{}{
				"upn": "exists",
			},
			ret:  "exists",
			name: "upn",
		},
		{
			data: map[string]interface{}{
				"unique_name": "exists",
			},
			ret:  "exists",
			name: "unique_name",
		},
		{
			data: map[string]interface{}{
				"fail": "exists",
			},
			ret:  "",
			name: "fail",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := findUsernameInClaims(tc.data)
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
