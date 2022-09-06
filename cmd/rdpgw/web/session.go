package web

import (
	"github.com/gorilla/sessions"
	"log"
	"os"
)

type SessionManagerConf struct {
	SessionKey           []byte
	SessionEncryptionKey []byte
	StoreType            string
}

func (c *SessionManagerConf) Init() sessions.Store {
	if len(c.SessionKey) < 32 {
		log.Fatal("Session key too small")
	}
	if len(c.SessionEncryptionKey) < 32 {
		log.Fatal("Session key too small")
	}

	if c.StoreType == "file" {
		log.Println("Filesystem is used as session storage")
		return sessions.NewFilesystemStore(os.TempDir(), c.SessionKey, c.SessionEncryptionKey)
	} else {
		log.Println("Cookies are used as session storage")
		return sessions.NewCookieStore(c.SessionKey, c.SessionEncryptionKey)
	}
}
