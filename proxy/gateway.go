package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"njuconnect/core"
)

// Gateway 本地 HTTP/HTTPS 代理：
//   - 目标为校内资源时，把主机名改写为 *.atrust.nju.edu.cn 并携带门户会话回源；
//     遇 verify 跳转自动内部完成认证。
//   - 其余目标直连转发（不携带学校会话 Cookie）。
//   - 校内 HTTPS 由本地 CA 解密转发；其他 HTTPS 使用原始 CONNECT 隧道。

type Gateway struct {
	session   *core.Session
	plain     *http.Client // 直连转发（无学校 Cookie）
	ca        *CertAuthority
	listen    string
	transport *http.Transport
	connMu    sync.Mutex
	conns     map[net.Conn]struct{}
	closed    bool
}

func NewGateway(sess *core.Session, ca *CertAuthority, listen string) *Gateway {
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         core.NewDialer().DialContext,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        64,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	plain := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Gateway{
		session:   sess,
		plain:     plain,
		ca:        ca,
		listen:    listen,
		transport: transport,
		conns:     make(map[net.Conn]struct{}),
	}
}

// Serve 启动代理监听（阻塞）。
func (g *Gateway) Serve() error {
	log.Printf("[proxy] 本地代理监听 http://%s （请勿与 Clash 的 7897 冲突）", g.listen)
	return http.ListenAndServe(g.listen, g)
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/proxy.pac" && strings.HasPrefix(r.Host, "127.0.0.1:") {
		g.servePAC(w)
		return
	}
	if r.Method == http.MethodConnect {
		g.handleConnect(w, r)
		return
	}
	if r.URL.Host == "" {
		http.Error(w, "njuconnect: 期望代理协议请求", http.StatusBadRequest)
		return
	}
	g.handleHTTP(w, r)
}

func (g *Gateway) servePAC(w http.ResponseWriter) {
	_, port, err := net.SplitHostPort(g.listen)
	if err != nil {
		http.Error(w, "bad proxy address", http.StatusInternalServerError)
		return
	}
	if _, err := strconv.Atoi(port); err != nil {
		http.Error(w, "bad proxy port", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, `function FindProxyForURL(url, host) {
  host = host.toLowerCase();
	if (host == "nju.edu.cn" || dnsDomainIs(host, ".nju.edu.cn"))
    return "PROXY 127.0.0.1:%s";
  return "DIRECT";
}`, port)
}

func (g *Gateway) Close() {
	g.connMu.Lock()
	g.closed = true
	for conn := range g.conns {
		_ = conn.Close()
	}
	g.connMu.Unlock()
	g.transport.CloseIdleConnections()
}

func (g *Gateway) trackConn(conn net.Conn) bool {
	g.connMu.Lock()
	defer g.connMu.Unlock()
	if g.closed {
		return false
	}
	g.conns[conn] = struct{}{}
	return true
}

func (g *Gateway) untrackConn(conn net.Conn) {
	g.connMu.Lock()
	delete(g.conns, conn)
	g.connMu.Unlock()
}

// handleHTTP 处理普通代理请求（HTTP 绝对 URI 或 MITM 后的明文请求）。
func (g *Gateway) handleHTTP(w http.ResponseWriter, r *http.Request) {
	target, usesSession := g.mapRequest(r)
	if target == nil {
		http.Error(w, "njuconnect: 无法解析目标", http.StatusBadGateway)
		return
	}

	resp, err := g.forward(target, usesSession)
	if err != nil {
		log.Printf("[proxy] %s%s -> %v", r.Host, r.URL.Path, err)
		http.Error(w, "njuconnect: 上游请求失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	log.Printf("[proxy] %s %s%s -> %s (session=%v) => %d", r.Method, r.Host, r.URL.Path, target.URL.Host, usesSession, resp.StatusCode)
	defer resp.Body.Close()

	// 网关认证既可能是 HTTP 302，也可能是 HTTP 200 中的 JavaScript 跳转。
	if usesSession {
		finalResp, err := g.followGatewayAuth(resp)
		if err != nil {
			http.Error(w, "njuconnect: 网关认证流程失败: "+err.Error(), http.StatusBadGateway)
			return
		}
		resp = finalResp
		defer resp.Body.Close()
	}

	copyResponse(w, resp, r.Host, target.URL.Host, usesSession)
}

// mapRequest 决定请求去向：返回改写后的出站请求；usesSession 表示是否携带学校会话。
func (g *Gateway) mapRequest(r *http.Request) (*http.Request, bool) {
	inHost := r.Host
	if h := r.URL.Host; h != "" {
		inHost = h
	}
	inHostOnly, inPort := splitHostPort(inHost)
	scheme := "http"
	if r.TLS != nil || r.URL.Scheme == "https" {
		scheme = "https"
	}

	outURL := *r.URL
	usesSession := false

	switch {
	case inHostOnly == "vpn.nju.edu.cn":
		// 认证门户不能编码成普通资源主机。
		outURL.Scheme = "https"
		outURL.Host = inHost
		usesSession = true
	case core.IsGatewayHost(inHostOnly):
		// 浏览器已带重写域名：直通网关
		outURL.Scheme = "https"
		if inPort != "" && inPort != "443" {
			outURL.Host = inHostOnly + ":" + inPort
		} else {
			outURL.Host = inHostOnly
		}
		usesSession = true
	case shouldRewrite(inHostOnly):
		// 校内资源：改写为网关子域
		enc := core.EncodeHost(scheme, inHostOnly, inPort)
		outURL.Scheme = "https"
		outURL.Host = enc + "." + core.GatewayDomain()
		usesSession = true
	default:
		// 外部资源：原样直连
		outURL.Scheme = scheme
		outURL.Host = inHost
	}

	outReq, err := http.NewRequest(r.Method, outURL.String(), r.Body)
	if err != nil {
		return nil, false
	}
	copyHeaders(outReq.Header, r.Header)
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authorization")
	// Host 必须是出站主机
	outReq.Host = outURL.Host
	if usesSession {
		g.mergeSessionCookies(outReq, &outURL)
	}
	outReq = outReq.WithContext(r.Context())
	return outReq, usesSession
}

// mergeSessionCookies 合并本地会话 Cookie（门户会话、网关 JSESSIONID）与浏览器带来的
// 应用层 Cookie，同名时本地会话优先。
func (g *Gateway) mergeSessionCookies(req *http.Request, outURL *url.URL) {
	browser := map[string]string{}
	if raw := req.Header.Get("Cookie"); raw != "" {
		for _, kv := range strings.Split(raw, ";") {
			kv = strings.TrimSpace(kv)
			if i := strings.Index(kv, "="); i > 0 {
				browser[kv[:i]] = kv[i+1:]
			}
		}
	}
	for _, c := range g.session.Jar.Cookies(outURL) {
		browser[c.Name] = c.Value
	}
	if len(browser) == 0 {
		return
	}
	pairs := make([]string, 0, len(browser))
	for k, v := range browser {
		pairs = append(pairs, k+"="+v)
	}
	req.Header.Set("Cookie", strings.Join(pairs, "; "))
}

// forward 发送出站请求；usesSession 决定用会话客户端还是干净客户端。
func (g *Gateway) forward(req *http.Request, usesSession bool) (*http.Response, error) {
	if usesSession {
		return g.session.Do(req)
	}
	return g.plain.Do(req)
}

var gatewayScriptRedirect = regexp.MustCompile(`var locationUrl = "(https://[^" ]+)";`)

// gatewayNext returns only the university authentication transitions. Other redirects
// remain visible to the browser so application navigation keeps its normal semantics.
func gatewayNext(resp *http.Response) (string, error) {
	loc := ""
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc = resp.Header.Get("Location")
	} else if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Type") == "" {
		buf := make([]byte, 32769)
		n, err := io.ReadFull(resp.Body, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return "", err
		}
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf[:n]), resp.Body))
		if m := gatewayScriptRedirect.FindSubmatch(buf[:n]); len(m) == 2 {
			loc = string(m[1])
		}
	}
	if loc == "" {
		return "", nil
	}
	u, err := resp.Request.URL.Parse(loc)
	if err != nil || u.Scheme != "https" {
		return "", nil
	}
	if (u.Hostname() == "vpn.nju.edu.cn" && strings.HasPrefix(u.Path, "/controller/v1/public/verify")) ||
		(core.IsGatewayHost(u.Hostname()) && (resp.StatusCode == http.StatusOK || resp.Request.URL.Hostname() == "vpn.nju.edu.cn")) {
		return u.String(), nil
	}
	return "", nil
}

func (g *Gateway) followGatewayAuth(resp *http.Response) (*http.Response, error) {
	cur := resp
	for hop := 0; hop < 8; hop++ {
		loc, err := gatewayNext(cur)
		if err != nil {
			cur.Body.Close()
			return nil, err
		}
		if loc == "" {
			return cur, nil
		}
		cur.Body.Close()
		req, err := http.NewRequest(http.MethodGet, loc, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126")
		var err2 error
		cur, err2 = g.session.Do(req)
		if err2 != nil {
			return nil, err2
		}
	}
	cur.Body.Close()
	return nil, fmt.Errorf("认证跳转超过 8 次")
}

// copyResponse 把上游响应写回浏览器；Location / Set-Cookie 中的网关域名反向映射为原始主机。
func copyResponse(w http.ResponseWriter, resp *http.Response, inHost, outHost string, rewrite bool) {
	for k, vv := range resp.Header {
		for _, v := range vv {
			if rewrite {
				switch strings.ToLower(k) {
				case "location", "content-location":
					v = reverseMapURL(v)
				case "set-cookie":
					v = reverseMapCookie(v)
				case "content-security-policy", "strict-transport-security":
					continue
				}
			}
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// reverseMapURL 把响应中的 *.atrust.nju.edu.cn URL 还原为原始 URL（尽力而为）。
func reverseMapURL(u string) string {
	if !strings.Contains(u, core.GatewayDomain()) {
		return u
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	scheme, host, port, ok := core.DecodeRewrittenHost(parsed.Hostname())
	if !ok {
		return u
	}
	if port != "" && port != "80" && port != "443" {
		parsed.Host = host + ":" + port
	} else {
		parsed.Host = host
	}
	if parsed.Scheme == "https" && scheme == "http" {
		parsed.Scheme = "http"
	}
	return parsed.String()
}

// reverseMapCookie 把 Set-Cookie 的 Domain=*.atrust.nju.edu.cn 去掉域属性，
// 使浏览器将 Cookie 绑定到当前访问的（映射后）主机。
func reverseMapCookie(cv string) string {
	parts := strings.Split(cv, ";")
	var out []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "domain=") {
			continue // 去掉 Domain，让浏览器默认绑当前主机
		}
		out = append(out, trimmed)
	}
	return strings.Join(out, "; ")
}

// handleConnect 处理 CONNECT：MITM 解密后按明文代理处理。
func (g *Gateway) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	hostOnly, _ := splitHostPort(host)
	if !shouldRewrite(hostOnly) && !core.IsGatewayHost(hostOnly) {
		g.tunnelDirect(w, r)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "不支持劫持", http.StatusInternalServerError)
		return
	}
	clientConn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	if !g.trackConn(clientConn) {
		return
	}
	defer g.untrackConn(clientConn)

	// 先回复 200，随后伪装成目标服务器完成 TLS
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	_ = buf // 后续直接用原始 conn

	leaf, err := g.ca.LeafForHost(hostOnly)
	if err != nil {
		return
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{*leaf}}
	tlsConn := tls.Server(clientConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	// 在解密连接上循环处理 HTTP 请求
	reader := newBufReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = host
		req.Host = host
		req = req.WithContext(r.Context())
		respWriter := newRespWriter(tlsConn, req)
		g.handleHTTP(respWriter, req)
		if req.Close || respWriter.closeAfter {
			return
		}
	}
}

// tunnelDirect leaves TLS untouched for hosts outside the campus gateway.
func (g *Gateway) tunnelDirect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "不支持隧道连接", http.StatusInternalServerError)
		return
	}
	addr := r.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}
	upstream, err := core.NewDialer().DialContext(r.Context(), "tcp", addr)
	if err != nil {
		http.Error(w, "直连失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	clientConn, buffered, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	if !g.trackConn(clientConn) {
		return
	}
	defer g.untrackConn(clientConn)
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	go func() {
		_, _ = io.Copy(upstream, buffered)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	_, _ = io.Copy(clientConn, upstream)
}

// ---- 小工具 ----

func splitHostPort(h string) (string, string) {
	if i := strings.LastIndex(h, ":"); i > strings.LastIndex(h, "]") {
		return h[:i], h[i+1:]
	}
	return h, ""
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		switch strings.ToLower(k) {
		case "host", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// shouldRewrite 判断是否校内资源（v1 规则：nju.edu.cn 及其子域、私有网段 IP）。
func shouldRewrite(host string) bool {
	h := strings.ToLower(host)
	if strings.HasSuffix(h, ".nju.edu.cn") || h == "nju.edu.cn" {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	// 仅已知学校公网段自动走 Web 网关。私网地址可能是家庭局域网；
	// 在完整隧道实现前，不猜测其归属。
	return strings.HasPrefix(h, "219.219.")
}
