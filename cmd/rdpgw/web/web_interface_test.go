package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

func TestHandleHostList(t *testing.T) {
	tests := []struct {
		name          string
		hostSelection string
		hosts         []string
		authenticated bool
		expectedCount int
		expectedType  string
	}{
		{
			name:          "roundrobin mode",
			hostSelection: "roundrobin",
			hosts:         []string{"host1.example.com", "host2.example.com"},
			authenticated: true,
			expectedCount: 1,
			expectedType:  "roundrobin",
		},
		{
			name:          "unsigned mode",
			hostSelection: "unsigned",
			hosts:         []string{"host1.example.com", "host2.example.com", "host3.example.com"},
			authenticated: true,
			expectedCount: 3,
			expectedType:  "individual",
		},
		{
			name:          "any mode",
			hostSelection: "any",
			hosts:         []string{"host1.example.com"},
			authenticated: true,
			expectedCount: 1,
			expectedType:  "individual",
		},
		{
			name:          "signed mode",
			hostSelection: "signed",
			hosts:         []string{"host1.example.com", "host2.example.com"},
			authenticated: true,
			expectedCount: 2,
			expectedType:  "signed",
		},
		{
			name:          "unauthenticated user",
			hostSelection: "roundrobin",
			hosts:         []string{"host1.example.com"},
			authenticated: false,
			expectedCount: 0,
			expectedType:  "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create handler
			handler := &Handler{
				hostSelection: tt.hostSelection,
				hosts:         tt.hosts,
			}

			// Create request
			req := httptest.NewRequest("GET", "/api/v1/hosts", nil)
			w := httptest.NewRecorder()

			// Set identity context
			user := identity.NewUser()
			if tt.authenticated {
				user.SetUserName("testuser")
				user.SetAuthenticated(true)
				user.SetAuthTime(time.Now())
			}
			req = identity.AddToRequestCtx(user, req)

			// Call handler
			handler.HandleHostList(w, req)

			if !tt.authenticated {
				if w.Code != http.StatusUnauthorized {
					t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
				}
				return
			}

			// Check response
			if w.Code != http.StatusOK {
				t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
			}

			var hosts []Host
			err := json.Unmarshal(w.Body.Bytes(), &hosts)
			if err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			if len(hosts) != tt.expectedCount {
				t.Errorf("Expected %d hosts, got %d", tt.expectedCount, len(hosts))
			}

			if len(hosts) > 0 {
				switch tt.expectedType {
				case "roundrobin":
					if hosts[0].ID != "roundrobin" {
						t.Errorf("Expected roundrobin host, got %s", hosts[0].ID)
					}
				case "individual":
					if !strings.Contains(hosts[0].Name, tt.hosts[0]) {
						t.Errorf("Expected host name to contain %s, got %s", tt.hosts[0], hosts[0].Name)
					}
				case "signed":
					if !strings.Contains(hosts[0].Name, tt.hosts[0]) {
						t.Errorf("Expected host name to contain %s, got %s", tt.hosts[0], hosts[0].Name)
					}
				}

				// Check that first host is marked as default
				hasDefault := false
				for _, host := range hosts {
					if host.IsDefault {
						hasDefault = true
						break
					}
				}
				if !hasDefault {
					t.Error("Expected at least one host to be marked as default")
				}
			}
		})
	}
}

func TestHandleUserInfo(t *testing.T) {
	tests := []struct {
		name          string
		authenticated bool
		username      string
		authTime      time.Time
	}{
		{
			name:          "authenticated user",
			authenticated: true,
			username:      "john.doe@example.com",
			authTime:      time.Now(),
		},
		{
			name:          "unauthenticated user",
			authenticated: false,
			username:      "",
			authTime:      time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create handler
			handler := &Handler{}

			// Create request
			req := httptest.NewRequest("GET", "/api/v1/user", nil)
			w := httptest.NewRecorder()

			// Set identity context
			user := identity.NewUser()
			if tt.authenticated {
				user.SetUserName(tt.username)
				user.SetAuthenticated(true)
				user.SetAuthTime(tt.authTime)
			}
			req = identity.AddToRequestCtx(user, req)

			// Call handler
			handler.HandleUserInfo(w, req)

			if !tt.authenticated {
				if w.Code != http.StatusUnauthorized {
					t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
				}
				return
			}

			// Check response
			if w.Code != http.StatusOK {
				t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
			}

			var userInfo UserInfo
			err := json.Unmarshal(w.Body.Bytes(), &userInfo)
			if err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			if userInfo.Username != tt.username {
				t.Errorf("Expected username %s, got %s", tt.username, userInfo.Username)
			}

			if userInfo.Authenticated != tt.authenticated {
				t.Errorf("Expected authenticated %v, got %v", tt.authenticated, userInfo.Authenticated)
			}

			if tt.authenticated && userInfo.AuthTime.IsZero() {
				t.Error("Expected non-zero auth time for authenticated user")
			}
		})
	}
}

func TestHandleWebInterface(t *testing.T) {
	tests := []struct {
		name          string
		authenticated bool
		expectStatus  int
		expectContent string
	}{
		{
			name:          "authenticated user",
			authenticated: true,
			expectStatus:  http.StatusOK,
			expectContent: "RDP Gateway",
		},
		{
			name:          "unauthenticated user",
			authenticated: false,
			expectStatus:  http.StatusFound,
			expectContent: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create handler with minimal configuration
			handler := &Handler{
				templatesPath: "./templates",
			}
			handler.loadWebConfig()
			handler.loadHTMLTemplate()

			// Create request
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()

			// Set identity context
			user := identity.NewUser()
			if tt.authenticated {
				user.SetUserName("testuser")
				user.SetAuthenticated(true)
				user.SetAuthTime(time.Now())
			}
			req = identity.AddToRequestCtx(user, req)

			// Call handler
			handler.HandleWebInterface(w, req)

			// Check response
			if w.Code != tt.expectStatus {
				t.Errorf("Expected status %d, got %d", tt.expectStatus, w.Code)
			}

			if tt.authenticated {
				body := w.Body.String()
				if !strings.Contains(body, tt.expectContent) {
					t.Errorf("Expected response to contain %s", tt.expectContent)
				}

				// Check that it's a complete HTML document
				if !strings.Contains(body, "<!DOCTYPE html>") {
					t.Error("Expected complete HTML document")
				}

				// Check for key elements (using fallback template)
				expectedElements := []string{
					"serversGrid",
					"connectButton",
					"loadServers",
					"connectToServer",
				}

				for _, element := range expectedElements {
					if !strings.Contains(body, element) {
						t.Errorf("Expected HTML to contain %s", element)
					}
				}
			} else {
				// Check redirect location
				location := w.Header().Get("Location")
				if location != "/connect" {
					t.Errorf("Expected redirect to /connect, got %s", location)
				}
			}
		})
	}
}

func TestHostSelectionIntegration(t *testing.T) {
	// Test the full flow from host selection to RDP download
	tests := []struct {
		name          string
		hostSelection string
		hosts         []string
		queryParams   string
		expectHost    string
		expectError   bool
	}{
		{
			name:          "roundrobin selection",
			hostSelection: "roundrobin",
			hosts:         []string{"host1.com", "host2.com", "host3.com"},
			queryParams:   "",
			expectHost:    "", // Will be one of the hosts
			expectError:   false,
		},
		{
			name:          "unsigned specific host",
			hostSelection: "unsigned",
			hosts:         []string{"host1.com", "host2.com"},
			queryParams:   "?host=host2.com",
			expectHost:    "host2.com",
			expectError:   false,
		},
		{
			name:          "unsigned invalid host",
			hostSelection: "unsigned",
			hosts:         []string{"host1.com", "host2.com"},
			queryParams:   "?host=invalid.com",
			expectHost:    "",
			expectError:   true,
		},
		{
			name:          "any host allowed",
			hostSelection: "any",
			hosts:         []string{"host1.com"},
			queryParams:   "?host=any-host.com",
			expectHost:    "any-host.com",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create handler
			handler := &Handler{
				hostSelection:  tt.hostSelection,
				hosts:          tt.hosts,
				gatewayAddress: &url.URL{Host: "gateway.example.com"},
			}

			// Create request for RDP download
			req := httptest.NewRequest("GET", "/connect"+tt.queryParams, nil)
			w := httptest.NewRecorder()

			// Set authenticated user
			user := identity.NewUser()
			user.SetUserName("testuser")
			user.SetAuthenticated(true)
			user.SetAuthTime(time.Now())
			req = identity.AddToRequestCtx(user, req)

			// Mock the token generator to avoid errors
			handler.paaTokenGenerator = func(ctx context.Context, user, host string) (string, error) {
				return "mock-token", nil
			}

			// Call download handler
			handler.HandleDownload(w, req)

			if tt.expectError {
				if w.Code == http.StatusOK {
					t.Error("Expected error but got success")
				}
			} else {
				if w.Code != http.StatusOK {
					t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
				}

				// Check content type
				contentType := w.Header().Get("Content-Type")
				if contentType != "application/x-rdp" {
					t.Errorf("Expected Content-Type application/x-rdp, got %s", contentType)
				}

				// Check content disposition
				disposition := w.Header().Get("Content-Disposition")
				if !strings.Contains(disposition, "attachment") || !strings.Contains(disposition, ".rdp") {
					t.Errorf("Expected attachment disposition with .rdp file, got %s", disposition)
				}

				// Check RDP content for expected host
				body := w.Body.String()
				if tt.expectHost != "" {
					if !strings.Contains(body, tt.expectHost) {
						t.Errorf("Expected RDP content to contain host %s", tt.expectHost)
					}
				}

				// Check for gateway configuration
				if !strings.Contains(body, "gateway.example.com") {
					t.Error("Expected RDP content to contain gateway address")
				}

				if !strings.Contains(body, "mock-token") {
					t.Error("Expected RDP content to contain access token")
				}
			}
		})
	}
}
