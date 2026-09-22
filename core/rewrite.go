package core

import (
	"fmt"
	"net/url"
	"strings"
)

// Web 代理网关的子域名重写算法（逆向自门户 search_app.98e07623.js 函数 I）。
//
//	https://lib.nju.edu.cn/            -> https://lib-nju-edu-cn-s.atrust.nju.edu.cn/
//	http://x.nju.edu.cn:8080/a?b=1     -> https://x-nju-edu-cn-8080-p.atrust.nju.edu.cn/a?b=1
//
// 网关域名与端口来自资源 panConf（NJU: https, atrust.nju.edu.cn, 443）。

const (
	defaultGatewayDomain = "atrust.nju.edu.cn"
	defaultGatewayPort   = "443"
)

// GatewayDomain 返回 Web 代理网关的泛域名。
func GatewayDomain() string { return defaultGatewayDomain }

// RewriteTarget 把目标 URL 映射为网关 URL。
func RewriteTarget(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("解析 URL 失败: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("不支持的协议: %s", scheme)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("URL 缺少主机名")
	}
	port := u.Port()
	rewriteHost := EncodeHost(scheme, host, port)
	out := "https://" + rewriteHost + "." + defaultGatewayDomain
	if defaultGatewayPort != "443" {
		out += ":" + defaultGatewayPort
	}
	if u.Path != "" {
		out += u.Path
	}
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out, nil
}

// EncodeHost 按前端算法编码目标主机名。
func EncodeHost(scheme, host, port string) string {
	host = strings.ToLower(host)
	isHTTPS := scheme == "https" || scheme == "wss"
	defaultPort := "80"
	if isHTTPS {
		defaultPort = "443"
	}
	nonDefaultPort := port != "" && port != defaultPort

	var b strings.Builder
	for i := 0; i < len(host); i++ {
		ch := host[i]
		if ch == '-' {
			b.WriteString("--")
		} else if ch == '.' || ch == ':' {
			b.WriteByte('-')
		} else {
			b.WriteByte(ch)
		}
	}
	c := b.String()

	if nonDefaultPort {
		c = c + "-" + port + "-p"
	}
	if isHTTPS {
		c = c + "-s"
	}
	// IPv6 字面量（含":"的特征在编码后体现为连续段），按前端逻辑加后缀
	if strings.Contains(host, ":") {
		suffix := "-v6"
		if strings.Contains(host, ".") {
			suffix = "-v46"
		}
		c = strings.ReplaceAll(c, "[", "")
		c = strings.ReplaceAll(c, "]", "")
		c += suffix
		if strings.HasPrefix(c, "--") {
			c = "0" + c
		}
	}
	return c
}

// DecodeRewrittenHost 逆解析 *.atrust.nju.edu.cn 子域名 -> (scheme, host, port)。
// 规则（与 EncodeHost 互逆）：先剥 -v46/-v6 后缀，再剥 -s（https 标记），
// 再剥尾部 -<port>-p（非默认端口），最后 '--' 是转义的 '-'，单个 '-' 是 '.'。
func DecodeRewrittenHost(fullHost string) (scheme, host, port string, ok bool) {
	h := strings.ToLower(fullHost)
	suffix := "." + defaultGatewayDomain
	if !strings.HasSuffix(h, suffix) {
		return "", "", "", false
	}
	c := strings.TrimSuffix(h, suffix)
	if c == "" {
		return "", "", "", false
	}

	scheme = "http"
	// IPv6 标记
	if strings.HasSuffix(c, "-v46") || strings.HasSuffix(c, "-v6") {
		// 逆 IPv6 编码较为复杂，v1 暂不支持 IPv6 目标
		if strings.HasSuffix(c, "-v46") {
			c = strings.TrimSuffix(c, "-v46")
		} else {
			c = strings.TrimSuffix(c, "-v6")
		}
	}
	// https 标记
	if strings.HasSuffix(c, "-s") && !strings.HasSuffix(c, "--s") {
		scheme = "https"
		c = strings.TrimSuffix(c, "-s")
	}
	// 非默认端口: -<digits>-p
	if strings.HasSuffix(c, "-p") && !strings.HasSuffix(c, "--p") {
		body := strings.TrimSuffix(c, "-p")
		if idx := strings.LastIndex(body, "-"); idx > 0 && allDigits(body[idx+1:]) {
			port = body[idx+1:]
			c = body[:idx]
		}
	}
	if port == "" {
		port = "80"
		if scheme == "https" {
			port = "443"
		}
	}

	// 还原主机名：'--' -> 占位，'-' -> '.'，占位 -> '-'
	const ph = "\x00"
	c = strings.ReplaceAll(c, "--", ph)
	c = strings.ReplaceAll(c, "-", ".")
	c = strings.ReplaceAll(c, ph, "-")
	host = c
	return scheme, host, port, true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// IsGatewayHost 判断主机名是否为网关子域（浏览器直接以重写形式访问时直通网关）。
func IsGatewayHost(host string) bool {
	return strings.HasSuffix(strings.ToLower(host), "."+defaultGatewayDomain)
}
