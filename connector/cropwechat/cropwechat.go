package cropwechat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/alonexc/plugins/connector/cropwechat/i18n"
	"github.com/answerdev/answer/plugin"
	"github.com/segmentfault/pacman/log"
	"net/http"
	"net/url"
	"strings"
)

type Connector struct {
	Config *ConnectorConfig
}

type ConnectorConfig struct {
	AppID       string `json:"app_id"`
	AgentID     string `json:"agent_id"`
	CropSecret  string `json:"crop_secret"`
	RedirectURI string `json:"redirect_uri"`
	ProxyIP     string `json:"proxy_ip"`
}

func init() {
	plugin.Register(&Connector{
		Config: &ConnectorConfig{},
	})
}

func (g *Connector) Info() plugin.Info {
	return plugin.Info{
		Name:        plugin.MakeTranslator(i18n.InfoName),
		SlugName:    "cropwechat_connector",
		Description: plugin.MakeTranslator(i18n.InfoDescription),
		Author:      "Alonexc",
		Version:     "0.0.1",
		Link:        "https://github.com/Alonexc/plugins/tree/main/connector/cropwechat",
	}
}

func (g *Connector) ConnectorLogoSVG() string {
	return ""
}

func (g *Connector) ConnectorName() plugin.Translator {
	return plugin.MakeTranslator(i18n.ConnectorName)
}

func (g *Connector) ConnectorSlugName() string {
	return "cropwechat"
}

// ConnectorSender Constructing a code-sweeping login address
func (g *Connector) ConnectorSender(ctx *plugin.GinContext, receiverURL string) (redirectURL string) {
	oauthConfig := &Config{
		AppID:   g.Config.AppID,
		AgentID: g.Config.AgentID,
		Endpoint: Endpoint{
			AuthURL: "https://login.work.weixin.qq.com/wwlogin/sso/login",
		},
		RedirectURL: g.Config.RedirectURI,
	}
	return oauthConfig.AuthCodeURL("WWLogin")
}

// ConnectorReceiver Get the code and get the token according to the callback address,
// as well as the user's info
func (g *Connector) ConnectorReceiver(ctx *plugin.GinContext, receiverURL string) (userInfo plugin.ExternalLoginUserInfo, err error) {
	code := ctx.Query("code")
	proxyURL, err := url.Parse(g.Config.ProxyIP)
	if err != nil {
		log.Error("proxyIP failed", err)
		return
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	},
	}
	// Exchange code for token
	// 1.Get access_token of enterprise weibo via code
	tokenResp, err := client.Get(fmt.Sprintf(
		"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s",
		g.Config.AppID, g.Config.CropSecret))
	if err != nil {
		log.Errorf("failed getting token: %s", err)
		return
	}
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenData)
	if err != nil {
		log.Errorf("token data parsing failed: %s", tokenResp.Body)
		return
	}
	log.Infof(fmt.Sprintf("access_token=%s", tokenData.AccessToken))
	defer tokenResp.Body.Close()
	// 2.Get userid by access_token and code
	userIDResp, err := client.Get(fmt.Sprintf(
		"https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo?access_token=%s&code=%s",
		tokenData.AccessToken, code))
	if err != nil {
		log.Errorf("get userID failed: %s", err)
		return
	}
	err = json.NewDecoder(userIDResp.Body).Decode(&userIDData)
	if err != nil {
		log.Errorf("userID data parsing failed: %s", err)
		return
	}
	log.Infof(fmt.Sprintf("UserID = %s, OpenID = %s", userIDData.UserID, userIDData.OpenID))
	userIDResp.Body.Close()
	// 3.Get user info by access_token and userid
	userInfoResp, err := client.Get(fmt.Sprintf(
		"https://qyapi.weixin.qq.com/cgi-bin/user/get?access_token=%s&userid=%s",
		tokenData.AccessToken, userIDData.UserID))
	if err != nil {
		log.Errorf("get user info failed: %s", err)
		return
	}
	err = json.NewDecoder(userInfoResp.Body).Decode(&userInfoData)
	if err != nil {
		log.Errorf("user infoData parsing failed: %s", err)
		return
	}
	if len(userInfoData.Email) == 0 {
		userInfoData.Email = fmt.Sprintf("%s%s", userInfoData.UserID, "@webank.com")
	}
	userInfoResp.Body.Close()
	fmt.Println(fmt.Sprintf("UserID=%s, Name=%s, Email=%s, Avatar=%s",
		userInfoData.UserID, userInfoData.Name, userInfoData.Email, userInfoData.Avatar))

	// data conversion
	metaInfo, _ := json.Marshal(userInfoResp)
	userInfo = plugin.ExternalLoginUserInfo{
		ExternalID:  fmt.Sprintf("%s", userInfoData.UserID),
		DisplayName: userInfoData.UserID,
		Username:    userInfoData.UserID,
		Email:       userInfoData.Email,
		MetaInfo:    string(metaInfo),
		Avatar:      userInfoData.Avatar,
	}

	return userInfo, nil
}

func (g *Connector) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		{
			Name:        "app_id",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigAppIDTitle),
			Description: plugin.MakeTranslator(i18n.ConfigAppIDDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: g.Config.AppID,
		},
		{
			Name:        "agent_id",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigAgentIDTitle),
			Description: plugin.MakeTranslator(i18n.ConfigAgentIDDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: g.Config.AgentID,
		},
		{
			Name:        "crop_secret",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigCropSecretTitle),
			Description: plugin.MakeTranslator(i18n.ConfigCropSecretDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: g.Config.CropSecret,
		},
		{
			Name:        "redirect_uri",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigRedirectURITitle),
			Description: plugin.MakeTranslator(i18n.ConfigRedirectURIDescription),
			Required:    false,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: g.Config.RedirectURI,
		},
		{
			Name:        "proxy_ip",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigProxyIPTitle),
			Description: plugin.MakeTranslator(i18n.ConfigProxyIPDescription),
			Required:    false,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: g.Config.ProxyIP,
		},
	}
}

func (g *Connector) ConfigReceiver(config []byte) error {
	c := &ConnectorConfig{}
	_ = json.Unmarshal(config, c)
	g.Config = c
	return nil
}

var tokenData struct {
	ErrCode     int    `json:"errcode"`
	ErrMsg      string `json:"errmsg"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

var userIDData struct {
	ErrCode        int    `json:"errcode"`
	ErrMsg         string `json:"errmsg"`
	UserID         string `json:"userid"`
	OpenID         string `json:"openid"`
	UserTicket     string `json:"user_ticket"`
	ExternalUserID string `json:"external_userid"`
}

var userInfoData struct {
	UserID    string `json:"userid"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Avatar    string `json:"avatar"`
	Position  string `json:"position"`
	Gender    string `json:"gender"`
	Telephone string `json:"telephone"`
	Alias     string `json:"alias"`
}

type AuthCodeOption interface {
	setValue(url.Values)
}

type Config struct {
	AppID string

	AgentID string

	CropSecret string

	Endpoint Endpoint

	RedirectURL string

	ProxyIP string
}

type Endpoint struct {
	AuthURL     string
	TokenURL    string
	UserIDURL   string
	UserInfoURL string
}

func (c *Config) AuthCodeURL(state string) string {
	var buf bytes.Buffer
	buf.WriteString(c.Endpoint.AuthURL)
	v := url.Values{
		"login_type": {"CorpApp"},
		"appid":      {c.AppID},
		"agentid":    {c.AgentID},
	}
	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}

	if state != "" {
		// TODO(light): Docs say never to omit state; don't allow empty.
		v.Set("state", state)
	}

	if strings.Contains(c.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	log.Infof(fmt.Sprintf("oauthURL=%s", buf.String()))
	return buf.String()
}
