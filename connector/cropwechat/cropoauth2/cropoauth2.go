package cropoauth2

import (
	"bytes"
	"net/url"
	"strings"
)

const (
	// AuthStyleAutoDetect means to auto-detect which authentication
	// style the provider wants by trying both ways and caching
	// the successful way for the future.
	AuthStyleAutoDetect AuthStyle = 0

	// AuthStyleInParams sends the "client_id" and "client_secret"
	// in the POST body as application/x-www-form-urlencoded parameters.
	AuthStyleInParams AuthStyle = 1

	// AuthStyleInHeader sends the client_id and client_password
	// using HTTP Basic Authorization. This is an optional style
	// described in the OAuth2 RFC 6749 section 2.3.1.
	AuthStyleInHeader AuthStyle = 2
)

type AuthCodeOption interface {
	setValue(url.Values)
}

type Config struct {
	AppID string

	AgentID string

	CropSecret string

	Endpoint Endpoint

	RedirectURL string

	//Scopes []string
}

type Endpoint struct {
	AuthURL     string
	TokenURL    string
	UserIDURL   string
	UserInfoURL string

	AuthStyle AuthStyle
}

type AuthStyle int

func (c *Config) AuthCodeURL(state string) string {
	var buf bytes.Buffer
	buf.WriteString(c.Endpoint.AuthURL)
	v := url.Values{
		"login_type": {"CorpApp"},
		//"response_type": {"code"},
		"appid":   {c.AppID},
		"agentid": {c.AgentID},
	}
	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}
	//if len(c.Scopes) > 0 {
	//	v.Set("scope", strings.Join(c.Scopes, " "))
	//}
	if state != "" {
		// TODO(light): Docs say never to omit state; don't allow empty.
		v.Set("state", state)
	}
	//for _, opt := range opts {
	//	opt.setValue(v)
	//}
	if strings.Contains(c.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}
