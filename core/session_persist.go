package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// 持久化结构：Cookie + CSRF token 一起存，login/verify 两步之间复用。
type PersistedSession struct {
	CSRF      string          `json:"csrf"`
	SMSAuthId string          `json:"smsAuthId,omitempty"`
	Cookies   []*storedCookie `json:"cookies"`
}

// Save 把会话（Cookie + CSRF）写入文件。
func (s *Session) Save(path string) error {
	s.Jar.mu.Lock()
	cookies := make([]*storedCookie, len(s.Jar.cookies))
	copy(cookies, s.Jar.cookies)
	s.Jar.mu.Unlock()
	ps := PersistedSession{CSRF: s.csrfToken, SMSAuthId: s.SMSAuthId, Cookies: cookies}
	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return SecureFile(path)
}

// Load 从文件恢复会话。
func (s *Session) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := SecureFile(path); err != nil {
		return err
	}
	var ps PersistedSession
	if err := json.Unmarshal(data, &ps); err != nil {
		return err
	}
	s.Jar.mu.Lock()
	s.Jar.cookies = ps.Cookies
	s.Jar.mu.Unlock()
	s.setCsrfToken(ps.CSRF)
	s.SMSAuthId = ps.SMSAuthId
	return nil
}

// SendSMSCode 请求发送短信验证码。
func (s *Session) SendSMSCode(authId string) error {
	url := fmt.Sprintf("%s/passport/v1/auth/sms?action=sendsms&%s&authId=%s", portalBase, clientParams, authId)
	var env jsonEnvelope
	resp, err := s.Client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK || env.Code != 0 {
		return fmt.Errorf("发送验证码失败: HTTP %d code=%d message=%s", resp.StatusCode, env.Code, env.Message)
	}
	return nil
}

// CheckSMSCode 提交短信验证码。成功后服务器会话即建立，新 Cookie 只在该响应
// 下发一次（已入 jar），调用方必须立即 Save 再继续 FinishAuth，否则会话丢失。
func (s *Session) CheckSMSCode(authId, code string) error {
	checkURL := fmt.Sprintf("%s/passport/v1/auth/sms?action=checkcode&%s", portalBase, clientParams)
	payload := map[string]string{
		"code":              code,
		"authId":            authId,
		"skipSecondaryAuth": "0",
		"isPrevEffect":      "0",
	}
	if err := s.callAPIRaw(http.MethodPost, checkURL, payload, nil); err != nil {
		return fmt.Errorf("checkcode: %w", err)
	}
	return nil
}
