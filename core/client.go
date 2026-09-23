package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ---- 可序列化的 CookieJar（支持持久化与跨域枚举） ----

type storedCookie struct {
	Name     string     `json:"name"`
	Value    string     `json:"value"`
	Domain   string     `json:"domain"`
	Path     string     `json:"path"`
	Expires  *time.Time `json:"expires,omitempty"`
	Secure   bool       `json:"secure"`
	HttpOnly bool       `json:"httpOnly"`
	HostOnly bool       `json:"hostOnly"`
}

// jarItem 与 storedCookie 相同但含运行时字段
type jarItem = storedCookie

// SerializableJar 实现 http.CookieJar，可 JSON 持久化。
type SerializableJar struct {
	mu      sync.Mutex
	cookies []*jarItem
}

func NewSerializableJar() *SerializableJar { return &SerializableJar{} }

func domainMatch(host, domain string) bool {
	host = strings.ToLower(host)
	domain = strings.ToLower(domain)
	if domain == "" {
		return true
	}
	if strings.HasPrefix(domain, ".") {
		d := domain[1:]
		return host == d || strings.HasSuffix(host, "."+d)
	}
	// 标准 Cookie 语义：Domain=example.com 匹配 example.com 及其所有子域
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func pathMatch(reqPath, cookiePath string) bool {
	if cookiePath == "" || cookiePath == "/" {
		return true
	}
	if !strings.HasPrefix(reqPath, cookiePath) {
		return false
	}
	if len(reqPath) == len(cookiePath) {
		return true
	}
	return strings.HasSuffix(cookiePath, "/") || reqPath[len(cookiePath)] == '/'
}

func (j *SerializableJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range cookies {
		domain := strings.ToLower(strings.TrimPrefix(c.Domain, "."))
		if domain == "" {
			domain = strings.ToLower(u.Hostname())
		} else if !domainMatch(u.Hostname(), domain) {
			continue
		}
		path := c.Path
		if !strings.HasPrefix(path, "/") {
			path = "/"
			if i := strings.LastIndex(u.Path, "/"); i > 0 {
				path = u.Path[:i]
			}
		}
		item := &jarItem{
			Name: c.Name, Value: c.Value, Domain: domain, Path: path,
			Secure: c.Secure, HttpOnly: c.HttpOnly,
			HostOnly: c.Domain == "",
		}
		if c.MaxAge < 0 {
			exp := time.Unix(0, 0)
			item.Expires = &exp
		} else if c.MaxAge > 0 {
			seconds := c.MaxAge
			if seconds > 2147483647 {
				seconds = 2147483647
			}
			exp := time.Now().Add(time.Duration(seconds) * time.Second)
			item.Expires = &exp
		} else if !c.Expires.IsZero() {
			exp := c.Expires
			item.Expires = &exp
		}
		// 同名同域同路径覆盖
		replaced := false
		for i, old := range j.cookies {
			if old.Name == item.Name && strings.EqualFold(old.Domain, item.Domain) && old.Path == item.Path {
				j.cookies[i] = item
				replaced = true
				break
			}
		}
		if !replaced {
			j.cookies = append(j.cookies, item)
		}
	}
	// 清理过期
	now := time.Now()
	kept := j.cookies[:0]
	for _, c := range j.cookies {
		if c.Expires != nil && now.After(*c.Expires) {
			continue
		}
		kept = append(kept, c)
	}
	j.cookies = kept
}

func (j *SerializableJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []*http.Cookie
	host := strings.ToLower(u.Hostname())
	for _, c := range j.cookies {
		if c.Expires != nil && time.Now().After(*c.Expires) {
			continue
		}
		if u.Scheme == "https" || !c.Secure {
			if (host == c.Domain || !c.HostOnly && domainMatch(host, c.Domain)) && pathMatch(u.Path, c.Path) {
				out = append(out, &http.Cookie{
					Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
					Secure: c.Secure, HttpOnly: c.HttpOnly,
				})
			}
		}
	}
	return out
}

// SaveToFile 导出为 JSON。
func (j *SerializableJar) SaveToFile(path string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	data, err := json.MarshalIndent(j.cookies, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadFromFile 导入 JSON。
func (j *SerializableJar) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err // 文件不存在视为无会话
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return json.Unmarshal(data, &j.cookies)
}

// ---- 会话（HTTP 客户端封装） ----

// Session 管理门户与网关的 Cookie 会话。
type Session struct {
	Jar       *SerializableJar
	Client    *http.Client
	Agent     *AgentClient
	csrfToken string
	// SMSAuthId 二次验证上下文（authCheck 返回 auth/sms 时填充）
	SMSAuthId string
	// pendingEnvHeader 一次性 x-sdp-env 请求头（下一个请求消费后清空）
	pendingEnvHeader string
}

// SetEnvHeader 设置下个请求携带的 x-sdp-env 值。
func (s *Session) SetEnvHeader(v string) { s.pendingEnvHeader = v }

func (s *Session) getCsrfToken() string { return s.csrfToken }
func (s *Session) setCsrfToken(t string) {
	s.csrfToken = t
}

// NewSession 创建直连（不走系统代理/Clash）、公共 DNS 解析的会话。
func NewSession() (*Session, error) {
	jar := NewSerializableJar()
	transport := &http.Transport{
		Proxy:                 nil, // 直连，绝不经过系统代理/Clash
		DialContext:           NewDialer().DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &Session{
		Jar:   jar,
		Agent: NewAgentClient(),
		Client: &http.Client{
			Transport: transport,
			Jar:       jar,
			Timeout:   60 * time.Second,
			// 不自动跟随重定向：verify 流程需要逐跳控制
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Do 发送请求（自动携带 Cookie）。
func (s *Session) Do(req *http.Request) (*http.Response, error) {
	return s.Client.Do(req)
}

type jsonEnvelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// DebugEnvelope 暴露给调试程序使用（与内部信封结构一致）。
type DebugEnvelope jsonEnvelope

// callEnv 执行请求并返回完整 JSON 信封（body 非 nil 时为 POST JSON）。
// 自动携带 x-csrf-token / x-sdp-traceid；遇到 code=10000001（CSRF 失效）
// 时用响应下发的新 token 重试一次。
func (s *Session) callEnv(method, rawURL string, body interface{}) (*jsonEnvelope, error) {
	env, err := s.doOnce(method, rawURL, body)
	if err != nil {
		return nil, err
	}
	if env.Code == codeCsrfInvalid {
		if tok := env.csrfTokenFromData(); tok != "" {
			s.setCsrfToken(tok)
			return s.doOnce(method, rawURL, body)
		}
	}
	return env, nil
}

const codeCsrfInvalid = 10000001

func (e *jsonEnvelope) csrfTokenFromData() string {
	var d struct {
		CsrfToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return ""
	}
	return d.CsrfToken
}

func (s *Session) doOnce(method, rawURL string, body interface{}) (*jsonEnvelope, error) {
	var bodyReader *strings.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = strings.NewReader(string(data))
	}
	var req *http.Request
	var err error
	if bodyReader != nil {
		req, err = http.NewRequest(method, rawURL, bodyReader)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json;charset=utf-8")
	} else {
		req, err = http.NewRequest(method, rawURL, nil)
		if err != nil {
			return nil, err
		}
	}
	req.Header.Set("x-csrf-token", s.getCsrfToken())
	req.Header.Set("x-sdp-traceid", RandomHex(4))
	if s.pendingEnvHeader != "" {
		req.Header.Set("x-sdp-env", s.pendingEnvHeader)
		s.pendingEnvHeader = ""
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// CSRF 失效常以 400 + code=10000001 返回，尝试解析
		var env jsonEnvelope
		if jerr := json.Unmarshal(raw, &env); jerr == nil && env.Code == codeCsrfInvalid {
			return &env, nil
		}
		return nil, fmt.Errorf("%s -> HTTP %d body=%.300s", rawURL, resp.StatusCode, string(raw))
	}
	var env jsonEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

func (e *jsonEnvelope) decodeInto(out interface{}) error {
	if e.Code != 0 {
		return fmt.Errorf("code=%d message=%s", e.Code, e.Message)
	}
	if out != nil && len(e.Data) > 0 {
		return json.Unmarshal(e.Data, out)
	}
	return nil
}

// GetJSONPublic 调试用：GET 并返回原始响应体。
func (s *Session) GetJSONPublic(rawURL string) ([]byte, error) {
	resp, err := s.Client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// PostJSONRaw 调试用：POST JSON 并返回原始响应体（不做状态码/信封检查）。
func (s *Session) PostJSONRaw(rawURL string, body interface{}) ([]byte, error) {
	env, err := s.doOnce(http.MethodPost, rawURL, body)
	if err != nil {
		// doOnce 对非200返回 error，这里把 error 文本原样给出
		return nil, err
	}
	out, _ := json.Marshal(env)
	return out, nil
}

// PostJSONRawWithEnv 调试用：POST JSON 并附加 x-sdp-env 头。
func (s *Session) PostJSONRawWithEnv(rawURL string, body interface{}, envBlob string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, toReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.getCsrfToken())
	req.Header.Set("x-sdp-traceid", RandomHex(4))
	if envBlob != "" {
		req.Header.Set("x-sdp-env", envBlob)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// GetJSON GET 并把 data 解到 out（code!=0 报错）。
func (s *Session) GetJSON(rawURL string, out interface{}) error {
	env, err := s.callEnv(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	return env.decodeInto(out)
}

// PostJSON POST JSON 并把 data 解到 out（code!=0 报错）。
func (s *Session) PostJSON(rawURL string, body, out interface{}) error {
	env, err := s.callEnv(http.MethodPost, rawURL, body)
	if err != nil {
		return err
	}
	return env.decodeInto(out)
}

// GetCsrfToken 导出当前 CSRF token（调试用）。
func (s *Session) GetCsrfToken() string { return s.getCsrfToken() }
