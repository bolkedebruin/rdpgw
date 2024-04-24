package database

import (
	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
	"testing"
)

func createTestDatabase () (Database) {
	var users = []config.UserConfig{}

	user1 := config.UserConfig{}
	user1.Username = "my_username"
	user1.Password = "my_password"
	users = append(users, user1)

	user2 := config.UserConfig{}
	user2.Username = "my_username2"
	user2.Password = "my_password2"
	users = append(users, user2)

	config := NewConfig(users)

	return config
}

func TestDatabaseConfigValidUsername(t *testing.T) {
	database := createTestDatabase()

	if database.GetPassword("my_username") != "my_password" {
		t.Fatalf("Wrong password returned")
	}
	if database.GetPassword("my_username2") != "my_password2" {
		t.Fatalf("Wrong password returned")
	}
}

func TestDatabaseInvalidUsername(t *testing.T) {
	database := createTestDatabase()

	if database.GetPassword("my_invalid_username") != "" {
		t.Fatalf("Non empty password returned for invalid username")
	}
}
