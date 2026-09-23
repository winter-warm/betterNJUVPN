//go:build windows

package gui

import "testing"

func TestOtherLocalProxyDetection(t *testing.T) {
	tests := []struct {
		name string
		v    winProxyValues
		want bool
	}{
		{"loopback server", winProxyValues{Enable: proxyDword{true, 1}, Server: proxyString{true, "127.0.0.1:7897"}}, true},
		{"disabled server", winProxyValues{Enable: proxyDword{true, 0}, Server: proxyString{true, "127.0.0.1:7897"}}, false},
		{"loopback PAC", winProxyValues{AutoConfig: proxyString{true, "http://localhost:9090/proxy.pac"}}, true},
		{"remote PAC", winProxyValues{AutoConfig: proxyString{true, "https://example.org/proxy.pac"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasOtherLocalProxy(tt.v); got != tt.want {
				t.Fatalf("hasOtherLocalProxy() = %v, want %v", got, tt.want)
			}
		})
	}
}
