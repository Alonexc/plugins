package cropwechat

import (
	"encoding/json"
	"fmt"
	"github.com/answerdev/answer/plugin"
	"github.com/answerdev/plugins/connector/github/cropoauth2"
	"github.com/answerdev/plugins/connector/github/i18n"
	"net/http"
)

type Connector struct {
	Config *ConnectorConfig
}

type ConnectorConfig struct {
	AppID      string `json:"app_id"`
	AgentID    string `json:"agent_id"`
	CropSecret string `json:"crop_secret"`
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

// 构造扫码登陆地址
func (g *Connector) ConnectorSender(ctx *plugin.GinContext, receiverURL string) (redirectURL string) {
	oauthConfig := &cropoauth2.Config{
		AppID:   g.Config.AppID,
		AgentID: g.Config.AgentID,
		Endpoint: cropoauth2.Endpoint{
			AuthURL:  "https://login.work.weixin.qq.com/wwlogin/sso/login",
			TokenURL: "https://qyapi.weixin.qq.com/cgi-bin/gettoken",
		},
		RedirectURL: receiverURL,
		//Scopes:      []string{"user:email"},
	}
	return oauthConfig.AuthCodeURL("WWLogin")
}

// 根据回调地址获取code以及获取token，以及用户信息
func (g *Connector) ConnectorReceiver(ctx *plugin.GinContext, receiverURL string) (userInfo plugin.ExternalLoginUserInfo, err error) {
	code := ctx.Query("code")
	// Exchange code for token
	// 1.通过code获取企业微信的access_token
	tokenResp, err := http.Get(fmt.Sprintf(
		"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s",
		g.Config.AppID, g.Config.CropSecret))
	if err != nil {
		fmt.Errorf("failed getting token: %s", err)
		return
	}
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenData)
	if err != nil {
		fmt.Errorf("token data parsing failed: %s", tokenResp.Body)
		return
	}
	fmt.Println(fmt.Sprintf("access_token=%s", tokenData.AccessToken))
	defer tokenResp.Body.Close()
	// 2.通过access_token和code获取userid
	userIDResp, err := http.Get(fmt.Sprintf(
		"https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo?access_token=%s&code=%s",
		tokenData.AccessToken, code))
	if err != nil {
		fmt.Errorf("get userID failed: %s", err)
		return
	}
	err = json.NewDecoder(userIDResp.Body).Decode(&userIDData)
	if err != nil {
		fmt.Errorf("userID data parsing failed: %s", err)
		return
	}
	fmt.Println(fmt.Sprintf("UserID = %s, OpenID = %s", userIDData.UserID, userIDData.OpenID))
	userIDResp.Body.Close()
	// 3.通过access_token和userid获取用户信息
	userInfoResp, err := http.Get(fmt.Sprintf(
		"https://qyapi.weixin.qq.com/cgi-bin/user/get?access_token=%s&userid=%s",
		tokenData.AccessToken, userIDData.UserID))
	if err != nil {
		fmt.Errorf("get user info faild: %s", err)
		return
	}
	err = json.NewDecoder(userInfoResp.Body).Decode(&userInfoData)
	if err != nil {
		fmt.Errorf("user infoData parsing failed: %s", err)
		return
	}
	userInfoResp.Body.Close()
	fmt.Println(fmt.Sprintf("UserID=%s, Name=%s, Email=%s, Avatar=%s",
		userInfoData.UserID, userInfoData.Name, userInfoData.Email, userInfoData.Avatar))

	//数据转换
	metaInfo, _ := json.Marshal(userInfoResp)
	userInfo = plugin.ExternalLoginUserInfo{
		ExternalID:  fmt.Sprintf("%s", userInfoData.UserID),
		DisplayName: userInfoData.Alias,
		Username:    userInfoData.Name,
		Email:       userInfoData.Email,
		MetaInfo:    string(metaInfo),
		Avatar:      userInfoData.Avatar,
	}

	// guarantee email was verified
	//userInfo.Email = g.guaranteeEmail(userInfo.Email, tokenData.AccessToken)
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
