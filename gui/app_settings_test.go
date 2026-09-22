package gui

import (
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"njuconnect/core"
)

func TestDisablingSystemProxyClosesLocalListener(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NJUCONNECT_CONFIG", filepath.Join(dir, "config.json"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	port := ln.Addr().(*net.TCPAddr).Port
	app := &App{
		state: StateOnline, cfg: &core.Config{ListenProxy: addr, DataDir: dir, ProxyMode: "rule", SystemProxy: "on"},
		proxyAddr: addr, proxyMode: "rule", systemProxyOn: true, proxyOn: true,
		tun: newTunManager(), systemProxy: newSystemProxyManager(dir), server: &http.Server{},
	}
	go app.server.Serve(ln)
	if err := app.UpdateSettings(port, false, "rule"); err != nil {
		t.Fatal(err)
	}
	if app.snapshot()["proxyOn"].(bool) {
		t.Fatal("proxy still marked running")
	}
	conn, err := net.Dial("tcp", addr)
	if err == nil {
		conn.Close()
		t.Fatal("local proxy port is still accepting connections")
	}
}
