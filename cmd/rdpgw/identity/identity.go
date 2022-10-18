package identity

import (
	"context"
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
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
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
