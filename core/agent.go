package core

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// 本地 aTrust Agent（aTrustAgent.exe）的 HTTP API。
// 浏览器登录流程中，"环境上报"这一步由 Agent 完成服务器侧通信；
// 本工具复用同一机制：psw 登录拿到 ticket 后，请 Agent 做报告，再进行 authCheck。
// Agent 未运行时返回错误，调用方自行降级（如半自动会话导入）。

const agentBase = "https://localhost.sangfor.com.cn:54631"

type AgentClient struct {
	http *http.Client
}

func NewAgentClient() *AgentClient {
	return &AgentClient{
		http: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Agent 使用本地自签证书
				Proxy:           nil,
			},
		},
	}
}

type agentEnvelope struct {
	Addr       string      `json:"addr"`
	Type       string      `json:"type"`
	Guid       string      `json:"guid"`
	Lang       string      `json:"lang"`
	SdpTraceId string      `json:"sdpTraceId"`
	Token      string      `json:"token"`
	Data       interface{} `json:"data"`
}

func (a *AgentClient) call(path string, guid string, data interface{}, out interface{}) error {
	payload := agentEnvelope{
		Addr:       portalBase,
		Type:       "web",
		Guid:       guid,
		Lang:       "zh-CN",
		SdpTraceId: RandomHex(4),
		Token:      "",
		Data:       data,
	}
	req, err := http.NewRequest(http.MethodPost, agentBase+path, toReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	// Agent 校验来源页（403 code=11119003 "请求非法"），必须带上门户的 Origin/Referer
	req.Header.Set("Origin", portalBase)
	req.Header.Set("Referer", portalBase+"/")
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("agent %s 不可达: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent %s -> HTTP %d", path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// ReportEnvBeforeLogin 请 Agent 完成登录前的环境上报（服务器侧）。
func (a *AgentClient) ReportEnvBeforeLogin(guid, ticket string) error {
	var resp struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	data := map[string]interface{}{
		"ticket": ticket,
		"timing": "pre-login",
	}
	err := a.call("/v1/service/reportEnvBeforeLogin", guid, data, &resp)
	if err != nil {
		return err
	}
	if resp.Code != 0 {
		return fmt.Errorf("agent reportEnv code=%d message=%s", resp.Code, resp.Message)
	}
	return nil
}

// GetEnv 向 Agent 请求环境密文（部分接口需要 x-sdp-env 头时使用）。
func (a *AgentClient) GetEnv(guid string) (string, error) {
	var resp struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := a.call("/v1/service/getEnv", guid, map[string]interface{}{}, &resp); err != nil {
		return "", err
	}
	if resp.Code != 0 {
		return "", fmt.Errorf("agent getEnv code=%d", resp.Code)
	}
	var d struct {
		EncryptEnv string `json:"encryptEnv"`
	}
	if err := json.Unmarshal(resp.Data, &d); err != nil {
		return "", err
	}
	return d.EncryptEnv, nil
}
