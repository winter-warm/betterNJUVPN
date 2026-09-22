package gui

import (
	"embed"
	"fmt"
	"net/http"

	webview2 "github.com/jchv/go-webview2"
)

//go:embed ui.html
var uiFS embed.FS

// serveUI 把内嵌 HTML 挂到 API 服务上（/ 路径），与 /api/* 同源。
func serveUI(mux *http.ServeMux) {
	html, err := uiFS.ReadFile("ui.html")
	if err != nil {
		return
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(html)
	})
}

// newWebView 创建 WebView2 窗口加载本地 UI；运行时缺失时返回错误（调用方回退浏览器）。
func newWebView(uiURL string) (webViewHandle, error) {
	wv := webview2.New(false)
	if wv == nil {
		return webViewHandle{}, fmt.Errorf("WebView2 运行时不可用")
	}
	wv.SetTitle("betterNJUVPN · 南京大学 Web VPN")
	wv.SetSize(1100, 760, 0)
	wv.Navigate(uiURL)
	return webViewHandle{w: wv}, nil
}

type webViewHandle struct {
	w webview2.WebView
}

func (h webViewHandle) Run() { h.w.Run() }
