package common

import (
	"context"
	"github.com/google/uuid"
	"net/http"
	"time"
)

const (
	CTXKey = "github.com/bolkedebruin/rdpgw/common/identity"

	AttrRemoteAddr  = "remoteAddr"
	AttrClientIp    = "clientIp"
	AttrProxies     = "proxyAddresses"
	AttrAccessToken = "accessToken" // todo remove for security reasons
)

type Identity interface {
	UserName() string
	SetUserName(string)
	DisplayName() string
	SetDisplayName(string)
	Domain() string
	SetDomain(string)
	Authenticated() bool
	SetAuthenticated(bool)
	AuthTime() time.Time
	SetAuthTime(time2 time.Time)
	SessionId() string
	SetAttribute(string, interface{})
	GetAttribute(string) interface{}
	Attributes() map[string]interface{}
	DelAttribute(string)
	Email() string
	SetEmail(string)
	Expiry() time.Time
	SetExpiry(time.Time)
}

func AddToRequestCtx(id Identity, r *http.Request) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, CTXKey, id)
	return r.WithContext(ctx)
}

func FromRequestCtx(r *http.Request) Identity {
	return FromCtx(r.Context())
}

func FromCtx(ctx context.Context) Identity {
	if id, ok := ctx.Value(CTXKey).(Identity); ok {
		return id
	}
	return nil
}

type User struct {
	authenticated   bool
	domain          string
	userName        string
	displayName     string
	email           string
	authTime        time.Time
	sessionId       string
	expiry          time.Time
	attributes      map[string]interface{}
	groupMembership map[string]bool
}

func NewUser() *User {
	uuid := uuid.New().String()
	return &User{
		attributes:      make(map[string]interface{}),
		groupMembership: make(map[string]bool),
		sessionId:       uuid,
	}
}

func (u *User) UserName() string {
	return u.userName
}

func (u *User) SetUserName(s string) {
	u.userName = s
}

func (u *User) DisplayName() string {
	if u.displayName == "" {
		return u.userName
	}
	return u.displayName
}

func (u *User) SetDisplayName(s string) {
	u.displayName = s
}

func (u *User) Domain() string {
	return u.domain
}

func (u *User) SetDomain(s string) {
	u.domain = s
}

func (u *User) Authenticated() bool {
	return u.authenticated
}

func (u *User) SetAuthenticated(b bool) {
	u.authenticated = b
}

func (u *User) AuthTime() time.Time {
	return u.authTime
}

func (u *User) SetAuthTime(t time.Time) {
	u.authTime = t
}

func (u *User) SessionId() string {
	return u.sessionId
}

func (u *User) SetAttribute(s string, i interface{}) {
	u.attributes[s] = i
}

func (u *User) GetAttribute(s string) interface{} {
	if found, ok := u.attributes[s]; ok {
		return found
	}
	return nil
}

func (u *User) Attributes() map[string]interface{} {
	return u.attributes
}

func (u *User) DelAttribute(s string) {
	delete(u.attributes, s)
}

func (u *User) Email() string {
	return u.email
}

func (u *User) SetEmail(s string) {
	u.email = s
}

func (u *User) Expiry() time.Time {
	return u.expiry
}

func (u *User) SetExpiry(t time.Time) {
	u.expiry = t
}
