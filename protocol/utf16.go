package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

func DecodeUTF16(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("must have even length byte slice")
	}

	u16s := make([]uint16, 1)
	ret := &bytes.Buffer{}
	b8buf := make([]byte, 4)

	lb := len(b)
	for i := 0; i < lb; i += 2 {
		u16s[0] = uint16(b[i]) + (uint16(b[i+1]) << 8)
		r := utf16.Decode(u16s)
		n := utf8.EncodeRune(b8buf, r[0])
		ret.Write(b8buf[:n])
	}

	bret := ret.Bytes()
	if len(bret) > 0 && bret[len(bret)-1] == '\x00' {
		bret = bret[:len(bret)-1]
	}
	return string(bret), nil
}

func EncodeUTF16(s string) []byte {
	ret := new(bytes.Buffer)
	enc := utf16.Encode([]rune(s))
	for c := range enc {
		binary.Write(ret, binary.LittleEndian, enc[c])
	}
	return ret.Bytes()
}