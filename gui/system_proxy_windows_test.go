//go:build windows

package gui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

// This test touches the user's Windows proxy settings, so it runs only when
// explicitly requested. The recovery file is kept until restoration succeeds.
func TestLiveSystemProxyRestore(t *testing.T) {
	if os.Getenv("NJUCONNECT_LIVE_PROXY_TEST") != "1" {
		t.Skip("live Windows proxy test")
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	before, err := readProxyValues(k)
	k.Close()
	if err != nil {
		t.Fatal(err)
	}
	m := newSystemProxyManager(t.TempDir())
	defer func() {
		if err := m.Restore(); err != nil {
			t.Errorf("restore: %v", err)
		}
	}()
	for _, mode := range []string{"rule", "global"} {
		if err := m.Enable("127.0.0.1:17999", mode); err != nil {
			t.Fatal(err)
		}
		if err := m.Restore(); err != nil {
			t.Fatal(err)
		}
	}
	k, err = registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	after, err := readProxyValues(k)
	k.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("Windows proxy settings did not restore")
	}
}

func TestEdgeUsesSystemProxyWithoutBrowserFlags(t *testing.T) {
	if os.Getenv("NJUCONNECT_LIVE_PROXY_TEST") != "1" {
		t.Skip("live Windows proxy test")
	}
	edge := `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
	if _, err := os.Stat(edge); err != nil {
		t.Skip("Edge unavailable")
	}
	seen := make(chan string, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.URL.String():
		default:
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><title>proxy-check</title></html>"))
	}))
	defer server.Close()
	m := newSystemProxyManager(t.TempDir())
	defer func() {
		if err := m.Restore(); err != nil {
			t.Errorf("restore: %v", err)
		}
	}()
	if err := m.Enable(strings.TrimPrefix(server.URL, "http://"), "global"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, edge, "--headless=new", "--disable-gpu", "--no-first-run",
		"--user-data-dir="+t.TempDir(), "--dump-dom", "http://example.com/njuconnect-proxy-check")
	output, commandErr := cmd.CombinedOutput()
	if len(seen) == 0 || !strings.Contains(string(output), "<title>proxy-check</title>") {
		t.Fatalf("Edge did not receive the local proxy response: %v, output=%q", commandErr, string(output))
	}
}

func TestEdgeUsesRulePACWithoutBrowserFlags(t *testing.T) {
	if os.Getenv("NJUCONNECT_LIVE_PROXY_TEST") != "1" {
		t.Skip("live Windows proxy test")
	}
	edge := `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
	if _, err := os.Stat(edge); err != nil {
		t.Skip("Edge unavailable")
	}
	var proxyAddress string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proxy.pac" && r.Host == proxyAddress {
			w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
			w.Write([]byte(`function FindProxyForURL(url, host) { if (dnsDomainIs(host, ".nju.edu.cn")) return "PROXY ` + proxyAddress + `"; return "DIRECT"; }`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><title>pac-proxy-check</title></html>"))
	}))
	defer server.Close()
	proxyAddress = strings.TrimPrefix(server.URL, "http://")
	m := newSystemProxyManager(t.TempDir())
	defer func() {
		if err := m.Restore(); err != nil {
			t.Errorf("restore: %v", err)
		}
	}()
	if err := m.Enable(proxyAddress, "rule"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, edge, "--headless=new", "--disable-gpu", "--no-first-run",
		"--user-data-dir="+t.TempDir(), "--dump-dom", "http://xk.nju.edu.cn/njuconnect-pac-check")
	output, err := cmd.CombinedOutput()
	if !strings.Contains(string(output), "<title>pac-proxy-check</title>") {
		t.Fatalf("Edge did not use the rule PAC: %v, output=%q", err, string(output))
	}
}
