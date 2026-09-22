//go:build windows

package gui

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTunConfigIsGlobalAndValid(t *testing.T) {
	cfg := tunConfig(7899, 38171, strings.Repeat("a", 64))
	for _, want := range []string{"device: njuConnectTun", "route-address:\n    - 0.0.0.0/1\n    - 128.0.0.0/1\n    - ::/1\n    - 8000::/1", "dns-hijack:\n    - any:53\n    - tcp://any:53", "fake-ip-range: 198.19.0.1/16", "port: 7899", "DOMAIN-SUFFIX,nju.edu.cn,NJU-Web", "MATCH,DIRECT"} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("missing %q", want)
		}
	}
	bin := filepath.Join("..", "tools", "mihomo", "mihomo-windows-amd64-compatible.exe")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("独立 Mihomo 核心未安装")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(file, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-t", "-d", dir, "-f", file).CombinedOutput()
	if err != nil {
		t.Fatalf("mihomo -t: %v\n%s", err, out)
	}
}
