package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

func init() {
	// Initialize session store for testing
	sessionKey := []byte("thisisasessionkeyreplacethisjetzt")
	encryptionKey := []byte("thisisasessionencryptionkey12345")
	InitStore(sessionKey, encryptionKey, "cookie", 8192)
}

func TestHeaderAuthenticated(t *testing.T) {
	cases := []struct {
		name               string
		headers            map[string]string
		expectedStatusCode int
		expectedAuth       bool
		expectedUser       string
		expectedEmail      string
		expectedDisplayName string
		expectedUserId     string
	}{
		{
			name: "ms_app_proxy_headers",
			headers: map[string]string{
				"X-MS-CLIENT-PRINCIPAL-NAME":  "user@domain.com",
				"X-MS-CLIENT-PRINCIPAL-ID":    "12345-abcdef",
				"X-MS-CLIENT-PRINCIPAL-EMAIL": "user@domain.com",
			},
			expectedStatusCode: http.StatusOK,
			expectedAuth:       true,
			expectedUser:       "user@domain.com",
			expectedEmail:      "user@domain.com",
			expectedUserId:     "12345-abcdef",
		},
		{
			name: "google_iap_headers",
			headers: map[string]string{
				"X-Goog-Authenticated-User-Email": "testuser@example.org",
				"X-Goog-Authenticated-User-ID":    "google-user-123",
			},
			expectedStatusCode: http.StatusOK,
			expectedAuth:       true,
			expectedUser:       "testuser@example.org",
			expectedEmail:      "testuser@example.org",
			expectedUserId:     "google-user-123",
		},
		{
			name: "aws_alb_headers",
			headers: map[string]string{
				"X-Amzn-Oidc-Subject": "aws-user-456",
				"X-Amzn-Oidc-Email":   "awsuser@company.com",
				"X-Amzn-Oidc-Name":    "AWS User",
			},
			expectedStatusCode:  http.StatusOK,
			expectedAuth:        true,
			expectedUser:        "aws-user-456",
			expectedEmail:       "awsuser@company.com",
			expectedDisplayName: "AWS User",
		},
		{
			name: "custom_headers",
			headers: map[string]string{
				"X-Forwarded-User":  "customuser",
				"X-Forwarded-Email": "custom@example.com",
				"X-Forwarded-Name":  "Custom User",
			},
			expectedStatusCode:  http.StatusOK,
			expectedAuth:        true,
			expectedUser:        "customuser",
			expectedEmail:       "custom@example.com",
			expectedDisplayName: "Custom User",
		},
		{
			name:               "missing_user_header",
			headers:            map[string]string{"X-Some-Other-Header": "value"},
			expectedStatusCode: http.StatusUnauthorized,
			expectedAuth:       false,
			expectedUser:       "",
		},
		{
			name:               "empty_headers",
			headers:            map[string]string{},
			expectedStatusCode: http.StatusUnauthorized,
			expectedAuth:       false,
			expectedUser:       "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test handler that checks the identity
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id := identity.FromRequestCtx(r)
				if id.Authenticated() != tc.expectedAuth {
					t.Errorf("expected authenticated: %v, got: %v", tc.expectedAuth, id.Authenticated())
				}
				if id.UserName() != tc.expectedUser {
					t.Errorf("expected username: %v, got: %v", tc.expectedUser, id.UserName())
				}
				if tc.expectedEmail != "" && id.Email() != tc.expectedEmail {
					t.Errorf("expected email: %v, got: %v", tc.expectedEmail, id.Email())
				}
				if tc.expectedDisplayName != "" && id.DisplayName() != tc.expectedDisplayName {
					t.Errorf("expected display name: %v, got: %v", tc.expectedDisplayName, id.DisplayName())
				}
				if tc.expectedUserId != "" {
					if userId := id.GetAttribute("user_id"); userId != tc.expectedUserId {
						t.Errorf("expected user_id: %v, got: %v", tc.expectedUserId, userId)
					}
				}
				w.WriteHeader(http.StatusOK)
			})

			// Determine header config based on test case
			var headerConfig *HeaderConfig
			switch tc.name {
			case "ms_app_proxy_headers":
				headerConfig = &HeaderConfig{
					UserHeader:        "X-MS-CLIENT-PRINCIPAL-NAME",
					UserIdHeader:      "X-MS-CLIENT-PRINCIPAL-ID",
					EmailHeader:       "X-MS-CLIENT-PRINCIPAL-EMAIL",
					DisplayNameHeader: "",
				}
			case "google_iap_headers":
				headerConfig = &HeaderConfig{
					UserHeader:   "X-Goog-Authenticated-User-Email",
					UserIdHeader: "X-Goog-Authenticated-User-ID",
					EmailHeader:  "X-Goog-Authenticated-User-Email",
				}
			case "aws_alb_headers":
				headerConfig = &HeaderConfig{
					UserHeader:        "X-Amzn-Oidc-Subject",
					EmailHeader:       "X-Amzn-Oidc-Email",
					DisplayNameHeader: "X-Amzn-Oidc-Name",
				}
			case "custom_headers":
				headerConfig = &HeaderConfig{
					UserHeader:        "X-Forwarded-User",
					EmailHeader:       "X-Forwarded-Email",
					DisplayNameHeader: "X-Forwarded-Name",
				}
			default:
				headerConfig = &HeaderConfig{
					UserHeader: "X-Forwarded-User",
				}
			}

			headerAuth := headerConfig.New()

			// Wrap test handler with authentication
			authHandler := headerAuth.Authenticated(testHandler)

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)

			// Add headers from test case
			for header, value := range tc.headers {
				req.Header.Set(header, value)
			}

			// Add identity to request context (simulating middleware)
			testId := identity.NewUser()
			req = identity.AddToRequestCtx(testId, req)

			// Create response recorder
			rr := httptest.NewRecorder()

			// Execute the handler
			authHandler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tc.expectedStatusCode {
				t.Errorf("expected status code: %v, got: %v", tc.expectedStatusCode, rr.Code)
			}
		})
	}
}

func TestHeaderAlreadyAuthenticated(t *testing.T) {
	// Create a test handler that checks the identity
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identity.FromRequestCtx(r)
		if !id.Authenticated() {
			t.Error("expected user to remain authenticated")
		}
		if id.UserName() != "existing_user" {
			t.Errorf("expected username to remain: existing_user, got: %v", id.UserName())
		}
		w.WriteHeader(http.StatusOK)
	})

	// Create header auth handler
	headerConfig := &HeaderConfig{
		UserHeader: "X-Forwarded-User",
	}
	headerAuth := headerConfig.New()

	// Wrap test handler with authentication
	authHandler := headerAuth.Authenticated(testHandler)

	// Create test request
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-User", "new_user@domain.com")

	// Add pre-authenticated identity to request context
	testId := identity.NewUser()
	testId.SetUserName("existing_user")
	testId.SetAuthenticated(true)
	testId.SetAuthTime(time.Now())
	req = identity.AddToRequestCtx(testId, req)

	// Create response recorder
	rr := httptest.NewRecorder()

	// Execute the handler
	authHandler.ServeHTTP(rr, req)

	// Check status code
	if rr.Code != http.StatusOK {
		t.Errorf("expected status code: %v, got: %v", http.StatusOK, rr.Code)
	}
}

func TestHeaderConfigValidation(t *testing.T) {
	cases := []struct {
		name   string
		config *HeaderConfig
		valid  bool
	}{
		{
			name: "valid_config",
			config: &HeaderConfig{
				UserHeader: "X-Forwarded-User",
			},
			valid: true,
		},
		{
			name: "full_config",
			config: &HeaderConfig{
				UserHeader:        "X-MS-CLIENT-PRINCIPAL-NAME",
				UserIdHeader:      "X-MS-CLIENT-PRINCIPAL-ID",
				EmailHeader:       "X-MS-CLIENT-PRINCIPAL-EMAIL",
				DisplayNameHeader: "X-MS-CLIENT-PRINCIPAL-NAME",
			},
			valid: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := tc.config.New()
			if header == nil && tc.valid {
				t.Error("expected valid header instance")
			}
		})
	}
}

func TestHeaderConfig(t *testing.T) {
	config := &HeaderConfig{}
	header := config.New()

	if header == nil {
		t.Error("expected non-nil Header instance")
	}
}

// Test that the authentication flow sets the correct attributes
func TestHeaderAttributesSetting(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identity.FromRequestCtx(r)

		// Check that auth time is set and recent
		authTime := id.AuthTime()
		if authTime.IsZero() {
			t.Error("expected auth time to be set")
		}
		if time.Since(authTime) > time.Minute {
			t.Error("auth time should be recent")
		}

		// Check that user_id attribute is set
		if userId := id.GetAttribute("user_id"); userId != "test-id-123" {
			t.Errorf("expected user_id: test-id-123, got: %v", userId)
		}

		w.WriteHeader(http.StatusOK)
	})

	headerConfig := &HeaderConfig{
		UserHeader:   "X-Forwarded-User",
		UserIdHeader: "X-Forwarded-User-Id",
	}
	headerAuth := headerConfig.New()
	authHandler := headerAuth.Authenticated(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-User", "user@domain.com")
	req.Header.Set("X-Forwarded-User-Id", "test-id-123")

	testId := identity.NewUser()
	req = identity.AddToRequestCtx(testId, req)

	rr := httptest.NewRecorder()
	authHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code: %v, got: %v", http.StatusOK, rr.Code)
	}
}