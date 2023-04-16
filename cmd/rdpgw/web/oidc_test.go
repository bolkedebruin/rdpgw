package web

import "testing"

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
