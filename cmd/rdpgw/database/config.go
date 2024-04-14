package database

import (
        "github.com/bolkedebruin/rdpgw/cmd/rdpgw/config"
)

type Config struct {
	users map[string]config.UserConfig
}

func NewConfig(users []config.UserConfig) *Config {
        usersMap := map[string]config.UserConfig{}
                
        for _, user := range users {
                usersMap[user.Username] = user
        }
        
	return &Config{
		users: usersMap,
	}
}

func (c *Config) GetPassword (username string) string {
        return c.users[username].Password
}