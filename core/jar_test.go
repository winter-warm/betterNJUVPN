package core

import (
	"net/http"
	"net/url"
	"testing"
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

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
