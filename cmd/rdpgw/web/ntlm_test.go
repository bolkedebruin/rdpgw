package web

import (
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
