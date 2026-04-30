package rdp

import (
	"log"
	"strings"
	"testing"
)

const (
	GatewayHostName = "my.yahoo.com"
)

func TestRdpBuilder(t *testing.T) {
	builder := NewBuilder()
	builder.Settings.GatewayHostname = "my.yahoo.com"
	builder.Settings.AutoReconnectionEnabled = true
	builder.Settings.SmartSizing = true

	s := builder.String()
	if !strings.Contains(s, "gatewayhostname:s:"+GatewayHostName+CRLF) {
		t.Fatalf("%s does not contain `gatewayhostname:s:%s", s, GatewayHostName)
	}
	if strings.Contains(s, "autoreconnection enabled") {
		t.Fatalf("autoreconnection enabled is in %s, but it's default value", s)
	}
	if !strings.Contains(s, "smart sizing:i:1"+CRLF) {
		t.Fatalf("%s does not contain smart sizing:i:1", s)
	}
	log.Printf("%s", builder.String())
}

func TestInitStruct(t *testing.T) {
	conn := RdpSettings{}
	initStruct(&conn)

	if conn.PromptCredentialsOnce != true {
		t.Fatalf("conn.PromptCredentialsOnce != true")
	}
}

func TestLoadFile(t *testing.T) {
	_, err := NewBuilderFromFile("rdp_test_file.rdp")
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}
}

func TestNormalizeRdpKey(t *testing.T) {
	cases := map[string]string{
		"use multimon": "usemultimon",
		"USE MULTIMON": "usemultimon",
		"  Use Multimon  ": "usemultimon",
		"audiomode":     "audiomode",
		"screen mode id": "screenmodeid",
	}
	for in, want := range cases {
		if got := NormalizeRdpKey(in); got != want {
			t.Errorf("NormalizeRdpKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestApplyOverrides_AllowedBoolApplies(t *testing.T) {
	b := NewBuilder()
	err := b.ApplyOverrides(
		map[string][]string{"usemultimon": {"1"}},
		[]string{"use multimon"},
	)
	if err != nil {
		t.Fatalf("ApplyOverrides returned error: %v", err)
	}
	if !b.Settings.UseMultimon {
		t.Errorf("UseMultimon = false, want true")
	}
	if !strings.Contains(b.String(), "use multimon:i:1"+CRLF) {
		t.Errorf("rendered file does not contain use multimon:i:1, got:\n%s", b.String())
	}
}

func TestApplyOverrides_AllowListNormalizes(t *testing.T) {
	// allow-list given with the human/rdp form; query uses URL-friendly form.
	b := NewBuilder()
	err := b.ApplyOverrides(
		map[string][]string{"USEMULTIMON": {"1"}},
		[]string{"Use Multimon"},
	)
	if err != nil {
		t.Fatalf("ApplyOverrides returned error: %v", err)
	}
	if !strings.Contains(b.String(), "use multimon:i:1"+CRLF) {
		t.Errorf("expected normalized match to apply override, got:\n%s", b.String())
	}
}

func TestApplyOverrides_DefaultValueStillSerializes(t *testing.T) {
	// UseMultimon defaults to false; the bare struct would skip serialization.
	// An explicit override of "0" must still emit `use multimon:i:0` so that
	// the operator's intent is signaled to the client.
	b := NewBuilder()
	err := b.ApplyOverrides(
		map[string][]string{"usemultimon": {"0"}},
		[]string{"use multimon"},
	)
	if err != nil {
		t.Fatalf("ApplyOverrides returned error: %v", err)
	}
	if !strings.Contains(b.String(), "use multimon:i:0"+CRLF) {
		t.Errorf("expected use multimon:i:0 to render despite matching default, got:\n%s", b.String())
	}
}

func TestApplyOverrides_RejectedWhenNotInAllowList(t *testing.T) {
	b := NewBuilder()
	err := b.ApplyOverrides(
		map[string][]string{"usemultimon": {"1"}},
		nil, // empty allow-list
	)
	if err == nil {
		t.Fatalf("ApplyOverrides accepted a key with empty allow-list")
	}
}

func TestApplyOverrides_UnknownKeysIgnored(t *testing.T) {
	// Query strings carry unrelated params (host=, etc.); these must not
	// trip an error.
	b := NewBuilder()
	err := b.ApplyOverrides(
		map[string][]string{"host": {"example.com"}, "totally-bogus": {"x"}},
		[]string{"use multimon"},
	)
	if err != nil {
		t.Errorf("ApplyOverrides should ignore unknown keys, got error: %v", err)
	}
}

func TestApplyOverrides_BoolValidation(t *testing.T) {
	cases := []struct {
		v       string
		wantErr bool
	}{
		{"0", false}, {"1", false},
		{"true", false}, {"false", false},
		{"TRUE", false},
		{"yes", true}, {"2", true}, {"", true}, {"abc", true},
	}
	for _, c := range cases {
		b := NewBuilder()
		err := b.ApplyOverrides(
			map[string][]string{"usemultimon": {c.v}},
			[]string{"use multimon"},
		)
		if (err != nil) != c.wantErr {
			t.Errorf("value %q: got err=%v, wantErr=%v", c.v, err, c.wantErr)
		}
	}
}

func TestApplyOverrides_IntValidation(t *testing.T) {
	b := NewBuilder()
	if err := b.ApplyOverrides(
		map[string][]string{"audiomode": {"2"}},
		[]string{"audiomode"},
	); err != nil {
		t.Fatalf("ApplyOverrides returned error: %v", err)
	}
	if b.Settings.AudioMode != 2 {
		t.Errorf("AudioMode = %d, want 2", b.Settings.AudioMode)
	}
	b2 := NewBuilder()
	if err := b2.ApplyOverrides(
		map[string][]string{"audiomode": {"hello"}},
		[]string{"audiomode"},
	); err == nil {
		t.Errorf("expected int parse error for value 'hello'")
	}
}

func TestApplyOverrides_StringField(t *testing.T) {
	b := NewBuilder()
	if err := b.ApplyOverrides(
		map[string][]string{"alternateshell": {"explorer.exe"}},
		[]string{"alternate shell"},
	); err != nil {
		t.Fatalf("ApplyOverrides returned error: %v", err)
	}
	if !strings.Contains(b.String(), "alternate shell:s:explorer.exe"+CRLF) {
		t.Errorf("expected alternate shell to be set, got:\n%s", b.String())
	}
}

func TestApplyOverrides_EmptyValueRejected(t *testing.T) {
	b := NewBuilder()
	err := b.ApplyOverrides(
		map[string][]string{"usemultimon": {""}},
		[]string{"use multimon"},
	)
	if err == nil {
		t.Errorf("expected error for empty value")
	}
}

func TestApplyOverrides_NilValuesNoOp(t *testing.T) {
	b := NewBuilder()
	if err := b.ApplyOverrides(nil, []string{"use multimon"}); err != nil {
		t.Errorf("ApplyOverrides(nil) should be a no-op, got: %v", err)
	}
}
