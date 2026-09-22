package core

import (
	"encoding/json"
	"testing"
)

func TestAuthConfigParse(t *testing.T) {
	raw := []byte(`{"domains":["a","b"],"pubKey":"ABC123","pubKeyExp":"65537","antiReplayRand":"0123abcd","defaultDomain":"local"}`)
	var cfg AuthConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Domains) != 2 || cfg.PubKey != "ABC123" || cfg.AntiReplay != "0123abcd" {
		t.Fatalf("解析失败: %+v", cfg)
	}
}
