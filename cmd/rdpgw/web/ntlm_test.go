package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetAuthPayloadShortHeader asserts that getAuthPayload tolerates
// Authorization header values shorter than the prefixes it tests for. The
// header value is attacker-controlled, so a sub-5-byte value must surface
// as an error rather than a slice-bounds panic that crashes the worker.
func TestGetAuthPayloadShortHeader(t *testing.T) {
	cases := []struct {
		name   string
		header string
		set    bool
	}{
		{"missing", "", false},
		{"empty", "", true},
		{"three chars", "abc", true},
		{"four chars", "NTLM", true},
		{"five chars not NTLM prefix", "abcde", true},
		{"nine chars Negotiate without trailing space", "Negotiate", true},
	}

	h := &NTLMAuthHandler{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tc.set {
				req.Header.Set("Authorization", tc.header)
			}

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("getAuthPayload panicked on Authorization=%q: %v", tc.header, r)
				}
			}()
			_, _, err := h.getAuthPayload(req)
			if err == nil {
				t.Errorf("expected error for Authorization=%q, got nil", tc.header)
			}
		})
	}
}

func TestNegotiateAuthDispatcher(t *testing.T) {
	var ntlmCalled, spnegoCalled bool

	ntlmH := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ntlmCalled = true
	})
	spnegoH := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spnegoCalled = true
	})

	dispatcher := NegotiateAuthDispatcher(spnegoH, ntlmH)

	// Case 1: Raw NTLMSSP Type 1 token in Negotiate header
	// "NTLMSSP\0\1\0\0\0" base64 is "TlRMTVNTUAABAAA..."
	reqNTLM := httptest.NewRequest("GET", "/", nil)
	reqNTLM.Header.Set("Authorization", "Negotiate TlRMTVNTUAABAAAA")
	rr := httptest.NewRecorder()
	dispatcher.ServeHTTP(rr, reqNTLM)

	if !ntlmCalled || spnegoCalled {
		t.Errorf("expected NTLM handler called for NTLMSSP payload, got ntlm=%v spnego=%v", ntlmCalled, spnegoCalled)
	}

	// Case 2: Kerberos token in Negotiate header
	ntlmCalled = false
	spnegoCalled = false
	reqKrb := httptest.NewRequest("GET", "/", nil)
	reqKrb.Header.Set("Authorization", "Negotiate YIIGfgYJKoZIhvcSAQICAQB...")
	rr = httptest.NewRecorder()
	dispatcher.ServeHTTP(rr, reqKrb)

	if !spnegoCalled || ntlmCalled {
		t.Errorf("expected SPNEGO handler called for Kerberos payload, got spnego=%v ntlm=%v", spnegoCalled, ntlmCalled)
	}
}
