package config

import (
	"encoding/json"
	"fmt"
	"log"
	"unicode"
)

// SingleChar is a single character taken from a configuration string, used
// for winbind's domain/user separator (DOMAIN<separator>user). Values that
// are longer than one character are tolerated on purpose: a warning shows
// the original value and the character that will actually be used, so a
// typo is visible but never prevents the daemon from starting.
type SingleChar rune

// String renders the character as the one-character string winbind sees.
// The zero value renders as the empty string; callers that need winbind's
// documented default separator fall back to DefaultSeparator.
func (c SingleChar) String() string {
	if c == 0 {
		return ""
	}
	return string(rune(c))
}

// newSingleChar normalizes a raw operator string into a SingleChar. Empty
// and control-character values fall back to the zero value (the documented
// samba default at render time); longer values are reduced to their first
// character. Every fallback is logged with the original value so operators
// can spot the typo.
func newSingleChar(raw string) SingleChar {
	runes := []rune(raw)
	if len(runes) == 0 {
		log.Printf("WARNING: winbind separator is empty: using samba's default %q", DefaultSeparator.String())
		return 0
	}
	if unicode.IsControl(runes[0]) {
		log.Printf("WARNING: winbind separator %q starts with a control character: using samba's default %q",
			raw, DefaultSeparator.String())
		return 0
	}
	if len(runes) > 1 {
		log.Printf("WARNING: winbind separator %q is %d characters long: using only the first character %q",
			raw, len(runes), string(runes[0]))
	}
	return SingleChar(runes[0])
}

// UnmarshalJSON decodes the documented YAML string form ("separator: +").
// Only the JSON type is strict (a number is not a character string); the
// content itself is normalized by newSingleChar.
func (c *SingleChar) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("winbind separator must be a single-character string: %w", err)
	}
	*c = newSingleChar(raw)
	return nil
}
