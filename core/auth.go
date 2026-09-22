package core

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

const (
	portalBase   = "https://vpn.nju.edu.cn"
	clientParams = "clientType=SDPBrowserClient&platform=Windows&lang=zh-CN"
)

// AuthConfig 对应 /passport/v1/public/authConfig 的 data。
type AuthConfig struct {
	Domains       []string `json:"domains"`
	PubKey        string   `json:"pubKey"`
	PubKeyExp     string   `json:"pubKeyExp"`
	AntiReplay    string   `json:"antiReplayRand"`
	DefaultDomain string   `json:"defaultDomain"`
	Guid          string   `json:"guid"`
	Security      struct {
		CsrfToken string `json:"csrfToken"`
	} `json:"security"`
}

// OnlineInfo 在线用户信息。
type OnlineInfo struct {
	Username  string `json:"username"`
	IsOnline  bool   `json:"isOnline"`
	UserID    string `json:"userId"`
	ClientIP  string `json:"clientIp"`
	Domain    string `json:"domain"`
	LoginTime string `json:"loginTime"`
	UserInfo  struct {
		Phone      string `json:"phone"`
		ExpireTime string `json:"expireTime"`
	} `json:"userInfo"`
}

// GetAuthConfig 拉取认证配置（公钥、认证域、防重放随机数、初始 CSRF token）。
func (s *Session) GetAuthConfig() (*AuthConfig, error) {
	var cfg AuthConfig
	url := fmt.Sprintf("%s/passport/v1/public/authConfig?%s&needTicket=1", portalBase, clientParams)
	if err := s.callAPIRaw(http.MethodGet, url, nil, &cfg); err != nil {
		return nil, fmt.Errorf("获取 authConfig 失败: %w", err)
	}
	if cfg.Security.CsrfToken != "" {
		s.setCsrfToken(cfg.Security.CsrfToken)
	}
	return &cfg, nil
}

// LoginLDAP 用学号密码走 LDAP 账号登录（auth/psw，NJU 域 openldap13924）。
func (s *Session) LoginLDAP(username, password, ldapDomain string) (*OnlineInfo, error) {
	cfg, err := s.GetAuthConfig()
	if err != nil {
		return nil, err
	}
	if cfg.PubKey == "" {
		return nil, ErrInvalidPubKey
	}
	if ldapDomain == "" {
		ldapDomain = pickLDAPDomain(cfg.Domains)
	}
	if ldapDomain == "" {
		return nil, fmt.Errorf("authConfig 未提供可用的账号认证域: %v", cfg.Domains)
	}

	// 密码明文 = 密码_antiReplayRand，Sangfor RSA（PKCS#1 v1.5），hex 输出
	plain := password + "_" + cfg.AntiReplay
	enc, err := SangforEncrypt(plain, cfg.PubKey, cfg.PubKeyExp)
	if err != nil {
		return nil, err
	}

	// 环境标识：免客户端模式下为自报 deviceId（与官方无 Agent 浏览器行为一致），
	// 放在 psw 请求的 x-sdp-env 头里；deviceId 持久化以保持设备稳定（授信绑定）。
	s.SetEnvHeader(s.ClientlessEnvBlob())

	loginURL := fmt.Sprintf("%s/passport/v1/auth/psw?%s", portalBase, clientParams)
	var authResp struct {
		Ticket      string `json:"ticket"`
		NextService string `json:"nextService"`
		AntiReplay  string `json:"antiReplayRand"`
		UserName    string `json:"userName"`
		Env         struct {
			Need   bool   `json:"need"`
			Timing string `json:"timing"`
		} `json:"env"`
	}
	err = s.callAPIRaw(http.MethodPost, loginURL, map[string]string{
		"username":    username + "@" + ldapDomain,
		"password":    enc,
		"rememberPwd": "0",
	}, &authResp)
	if err != nil {
		return nil, fmt.Errorf("auth/psw: %w", err)
	}

	// 注：官方浏览器+Agent 流程在此处会让 Agent 做环境上报（reportEnvBeforeLogin），
	// 但实测免客户端 deviceId 路径（x-sdp-env 头）已足够，Agent 上报对本会话无效。

	switch authResp.NextService {
	case "", "auth/authCheck":
		// 正常路径
	case "auth/sms", "auth/mailCheck", "auth/secondaryCert", "auth/totp":
		return nil, ErrNeedSMS
	default:
		log.Printf("[njuconnect] 登录后 nextService=%s，尝试继续", authResp.NextService)
	}

	info, err := s.FinishAuth()
	if err == ErrSMSPending {
		return nil, ErrSMSPending // s.SMSAuthId 已填充
	}
	return info, err
}

// FinishAuth 完成认证校验（authCheck），建立门户会话。
// 若返回需要短信二次验证，错误为 ErrSMSPending，且 s.SMSAuthId 已填充。
func (s *Session) FinishAuth() (*OnlineInfo, error) {
	checkURL := fmt.Sprintf("%s/passport/v1/auth/authCheck?%s", portalBase, clientParams)
	var checkResp struct {
		SidTicket       string `json:"sidTicket"`
		NextService     string `json:"nextService"`
		NextServiceList []struct {
			AuthId   string `json:"authId"`
			AuthType string `json:"authType"`
		} `json:"nextServiceList"`
		OnlineInfo OnlineInfo `json:"onlineInfo"`
	}
	if err := s.callAPIRaw(http.MethodGet, checkURL, nil, &checkResp); err != nil {
		// 75500006"当前账号已在线，无需重复上线"：会话本身有效，直接查在线信息
		if strings_Contains(err.Error(), "75500006") {
			if info, ierr := s.GetOnlineInfo(); ierr == nil && info.IsOnline {
				return info, nil
			}
		}
		return nil, fmt.Errorf("authCheck: %w", err)
	}
	if checkResp.NextService == "auth/sms" && len(checkResp.NextServiceList) > 0 {
		s.SMSAuthId = checkResp.NextServiceList[0].AuthId
		return nil, ErrSMSPending
	}
	return &checkResp.OnlineInfo, nil
}

// GetOnlineInfo 查询当前会话状态（doctor 与保活判断）。
func (s *Session) GetOnlineInfo() (*OnlineInfo, error) {
	url := fmt.Sprintf("%s/passport/v1/user/onlineInfo?%s", portalBase, clientParams)
	var info OnlineInfo
	if err := s.callAPIRaw(http.MethodGet, url, nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// RefreshSession 尝试用现有 Cookie 恢复在线状态：
// 再次 authCheck（服务器对已在线账号返回 75500006"已在线"时视为可恢复，重试一次）。
func (s *Session) RefreshSession() (*OnlineInfo, error) {
	info, err := s.FinishAuth()
	if err == nil && info != nil && info.IsOnline {
		return info, nil
	}
	// 75500006 已在线：重试一次 authCheck（服务器提示"请刷新后重试"）
	if err != nil && strings_Contains(err.Error(), "75500006") {
		return s.FinishAuth()
	}
	// 兜底：直接查在线信息
	return s.GetOnlineInfo()
}

func strings_Contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// pickLDAPDomain 从 domains 中挑选 LDAP 账号域（非 local、非 OAuth）。
func pickLDAPDomain(domains []string) string {
	for _, d := range domains {
		if d != "local" && d != "" && !isOAuthDomain(d) {
			return d
		}
	}
	for _, d := range domains {
		if d != "local" && d != "" {
			return d
		}
	}
	return ""
}

func isOAuthDomain(d string) bool {
	return len(d) > 6 && (d[:6] == "custom" || containsFold(d, "oauth"))
}

func containsFold(s, sub string) bool {
	n := len(sub)
	if n == 0 {
		return true
	}
	for i := 0; i+n <= len(s); i++ {
		if toLowerByte(s[i]) == toLowerByte(sub[0]) && equalFoldFrom(s[i:], sub) {
			return true
		}
	}
	return false
}

func equalFoldFrom(s, sub string) bool {
	for i := 0; i < len(sub); i++ {
		if toLowerByte(s[i]) != toLowerByte(sub[i]) {
			return false
		}
	}
	return true
}

func toLowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

// callAPIRaw 调门户 API：解 JSON 信封，code!=0 报错，data 解到 out。
func (s *Session) callAPIRaw(method, rawURL string, body, out interface{}) error {
	env, err := s.callEnv(method, rawURL, body)
	if err != nil {
		return err
	}
	if env.Code != 0 {
		if containsFold(env.Message, "验证码") {
			return ErrNeedCaptcha
		}
		return fmt.Errorf("code=%d message=%s", env.Code, env.Message)
	}
	if out != nil && len(env.Data) > 0 {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}
