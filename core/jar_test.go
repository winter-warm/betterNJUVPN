package core

import (
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

func TestJarDomainCookie(t *testing.T) {
	j := NewSerializableJar()
	u, _ := url.Parse("https://lib-nju-edu-cn-s.atrust.nju.edu.cn/?sdpAppCode=x")
	j.SetCookies(u, []*http.Cookie{{
		Name:   "sdp_user_token",
		Value:  "abc123",
		Path:   "/",
		Domain: "atrust.nju.edu.cn",
		Secure: true,
	}})
	got := j.Cookies(mustURL("https://lib-nju-edu-cn-s.atrust.nju.edu.cn/"))
	if len(got) == 0 {
		t.Fatal("cookie 丢失: 未按 domain=atrust.nju.edu.cn 匹配到子域请求")
	}
	if got[0].Name != "sdp_user_token" || got[0].Value != "abc123" {
		t.Fatalf("cookie 内容错误: %+v", got[0])
	}
}

func TestJarDeletionAndMaxAge(t *testing.T) {
	j := NewSerializableJar()
	u := mustURL("https://vpn.nju.edu.cn/")
	past := time.Now().Add(-time.Hour)
	j.SetCookies(u, []*http.Cookie{{Name: "session", Value: "live", MaxAge: 60, Expires: past}})
	if len(j.Cookies(u)) != 1 {
		t.Fatal("Max-Age must take precedence over Expires")
	}
	j.SetCookies(u, []*http.Cookie{{Name: "session", MaxAge: -1}})
	if got := j.Cookies(u); len(got) != 0 {
		t.Fatalf("deleted cookie still present: %v", got)
	}
}

func TestJarHostOnlyAndDefaultPathPersist(t *testing.T) {
	j := NewSerializableJar()
	j.SetCookies(mustURL("https://vpn.nju.edu.cn/auth/login"), []*http.Cookie{{Name: "session", Value: "test"}})
	path := filepath.Join(t.TempDir(), "cookies.json")
	if err := j.SaveToFile(path); err != nil {
		t.Fatal(err)
	}
	j = NewSerializableJar()
	if err := j.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"https://child.vpn.nju.edu.cn/auth/", "https://vpn.nju.edu.cn/other"} {
		if got := j.Cookies(mustURL(target)); len(got) != 0 {
			t.Fatalf("cookie escaped scope to %s: %v", target, got)
		}
	}
	if len(j.Cookies(mustURL("https://vpn.nju.edu.cn/auth/check"))) != 1 {
		t.Fatal("host-only cookie lost")
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
