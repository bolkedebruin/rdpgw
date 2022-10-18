package identity

import (
	"log"
	"testing"
)

func TestMarshalling(t *testing.T) {
	u := NewUser()
	u.SetUserName("ANAME")
	u.SetAuthenticated(true)
	u.SetDomain("DOMAIN")

	c := NewUser()
	data, err := u.Marshal()
	if err != nil {
		log.Fatalf("Cannot marshal %s", err)
	}

	err = c.Unmarshal(data)
	if err != nil {
		t.Fatalf("Error while unmarshalling: %s", err)
	}

	if u.UserName() != c.UserName() || u.Authenticated() != c.Authenticated() || u.Domain() != c.Domain() {
		t.Fatalf("identities not equal: %+v != %+v", u, c)
	}
}
