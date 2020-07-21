package security

import (
	"github.com/bolkedebruin/rdpgw/protocol"
	"github.com/patrickmn/go-cache"
	"log"
)

type Config struct {
	Store *cache.Cache
}

func (c *Config) VerifyPAAToken(s *protocol.SessionInfo, token string) (bool, error) {
	_, found := c.Store.Get(token)
	if !found {
		log.Printf("PAA Token %s not found", token)
		return false, nil
	}

	return true, nil
}