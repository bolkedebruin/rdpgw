package rdp

import (
	"bufio"
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type RDP struct{}

func Parser() *RDP {
	return &RDP{}
}

func (p *RDP) Unmarshal(b []byte) (map[string]interface{}, error) {
	r := bytes.NewReader(b)
	scanner := bufio.NewScanner(r)
	mp := make(map[string]interface{})

	c := 0
	for scanner.Scan() {
		c++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			return nil, fmt.Errorf("malformed line %d: %q", c, line)
		}

		key := strings.TrimSpace(fields[0])
		t := strings.TrimSpace(fields[1])
		val := strings.TrimSpace(fields[2])

		switch t {
		case "i":
			intValue, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("cannot parse integer at line %d: %s", c, line)
			}
			mp[key] = intValue
		case "s":
			mp[key] = val
		case "b":
			mp[key] = val
		default:
			return nil, fmt.Errorf("malformed line %d: %s", c, line)
		}
	}
	return mp, nil
}

func (p *RDP) Marshal(o map[string]interface{}) ([]byte, error) {
	var b bytes.Buffer

	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		v := o[key]
		switch v.(type) {
		case bool:
			if v == true {
				fmt.Fprintf(&b, "%s:i:1", key)
			} else {
				fmt.Fprintf(&b, "%s:i:0", key)
			}
		case int:
			fmt.Fprintf(&b, "%s:i:%d", key, v)
		case string:
			fmt.Fprintf(&b, "%s:s:%s", key, v)
		default:
			return nil, fmt.Errorf("error marshalling")
		}
		fmt.Fprint(&b, "\r\n")
	}
	return b.Bytes(), nil
}
