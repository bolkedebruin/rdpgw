package parsers

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUnmarshalRDPFile(t *testing.T) {
	rdp := Parser()

	testCases := []struct {
		name      string
		cfg       []byte
		expOutput map[string]interface{}
		err       error
	}{
		{
			name:      "empty",
			expOutput: map[string]interface{}{},
		},
		{
			name: "string",
			cfg:  []byte(`username:s:user1`),
			expOutput: map[string]interface{}{
				"username": "user1",
			},
		},
		{
			name: "integer",
			cfg:  []byte(`session bpp:i:32`),
			expOutput: map[string]interface{}{
				"session bpp": 32,
			},
		},
		{
			name: "multi",
			cfg:  []byte("compression:i:1\r\nusername:s:user2\r\n"),
			expOutput: map[string]interface{}{
				"compression": 1,
				"username":    "user2",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			outMap, err := rdp.Unmarshal(tc.cfg)
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.expOutput, outMap)
		})
	}
}

func TestRDP_Marshal(t *testing.T) {
	testCases := []struct {
		name   string
		input  map[string]interface{}
		output []byte
		err    error
	}{
		{
			name:   "Empty RDP",
			input:  map[string]interface{}{},
			output: []byte(nil),
		},
		{
			name: "Valid RDP all types",
			input: map[string]interface{}{
				"compression": 1,
				"session bpp": 32,
				"username":    "user1",
			},
			output: []byte("compression:i:1\r\nsession bpp:i:32\r\nusername:s:user1\r\n"),
		},
	}

	rdp := Parser()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := rdp.Marshal(tc.input)
			assert.Equal(t, tc.output, out)
			assert.Equal(t, tc.err, err)
		})
	}
}
