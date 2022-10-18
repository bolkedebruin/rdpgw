package web

import (
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"os"
)

const (
	rdpGwSession = "RDPGWSESSION"
	MaxAge       = 120
	identityKey  = "RDPGWID"
)

var sessionStore sessions.Store

func InitStore(sessionKey []byte, encryptionKey []byte, storeType string) {
	if len(sessionKey) < 32 {
		log.Fatal("Session key too small")
	}
	if len(encryptionKey) < 32 {
		log.Fatal("Session key too small")
	}

	if storeType == "file" {
		log.Println("Filesystem is used as session storage")
		sessionStore = sessions.NewFilesystemStore(os.TempDir(), sessionKey, encryptionKey)
	} else {
		log.Println("Cookies are used as session storage")
		sessionStore = sessions.NewCookieStore(sessionKey, encryptionKey)
	}
}

func GetSession(r *http.Request) (*sessions.Session, error) {
	session, err := sessionStore.Get(r, rdpGwSession)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func GetSessionIdentity(r *http.Request) (identity.Identity, error) {
	s, err := GetSession(r)
	if err != nil {
		return nil, err
	}

	idData := s.Values[identityKey]
	if idData == nil {
		return nil, nil

	}
	id := identity.NewUser()
	id.Unmarshal(idData.([]byte))
	return id, nil
}

func SaveSessionIdentity(r *http.Request, w http.ResponseWriter, id identity.Identity) error {
	session, err := GetSession(r)
	if err != nil {
		return err
	}
	session.Options.MaxAge = MaxAge

	idData, err := id.Marshal()
	if err != nil {
		return err
	}
	session.Values[identityKey] = idData

	return sessionStore.Save(r, w, session)

}
