package core

import (
	"context"
	"net"
	"time"
)

// NewPublicResolver 返回一个使用公共 DNS（阿里 223.5.5.5）的解析器。
// 南大校园网 DNS 对 vpn.nju.edu.cn 返回 NXDOMAIN（2026-09 实测），
// 因此工具出站解析一律走公共 DNS，避免被校园/本地 DNS 干扰。
func NewPublicResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "223.5.5.5:53")
		},
	}
}

// NewDialer 返回使用上述解析器的拨号器（直连，不走系统代理）。
func NewDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  NewPublicResolver(),
	}
}

// LookupPublic 用公共 DNS 解析主机名（诊断与代理回源共用）。
func LookupPublic(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return NewPublicResolver().LookupHost(ctx, host)
}
