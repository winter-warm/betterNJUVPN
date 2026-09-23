package gui

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime/debug"

	"njuconnect/core"
)

// Run 启动 GUI：本地 API 服务 + WebView2 窗口（不可用则回退到默认浏览器）。
// 关闭窗口 / 点击退出即停止代理；异常退出由独立监护恢复系统代理。
func Run() {
	enableHighDPI()
	release, err := acquireGUIInstance()
	if err != nil {
		fatalDialog(err.Error())
		return
	}
	defer release()
	cfg, err := core.LoadConfig()
	if err != nil {
		fatalDialog("配置文件损坏: " + err.Error())
		return
	}
	app, err := NewApp(cfg)
	if err != nil {
		fatalDialog("初始化失败: " + err.Error())
		return
	}

	// 本地 API 端口：动态挑选空闲端口
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatalDialog("本地端口分配失败: " + err.Error())
		return
	}
	apiAddr := ln.Addr().String()
	uiURL := "http://" + apiAddr + "/"
	log.Printf("[gui] UI 地址: %s", uiURL)

	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	serveUI(mux)
	go func() {
		errCh <- app.ServeAPI(ln, mux)
	}()

	// 主线程跑 WebView2（内部处理 COM）；失败则回退浏览器
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[gui] panic: %v\n%s\n", r, debug.Stack())
			fallbackBrowser(uiURL, errCh)
		}
	}()
	if ok := runWebView(uiURL, errCh); !ok {
		fallbackBrowser(uiURL, errCh)
	}
	if err := app.StopProxy(); err != nil {
		fmt.Fprintf(os.Stderr, "[gui] 恢复系统代理失败: %v\n", err)
	}
	os.Exit(0)
}

// runWebView 返回 false 表示 WebView2 不可用（未安装运行时等）。
func runWebView(uiURL string, errCh chan error) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[gui] webview 不可用: %v\n", r)
			ok = false
		}
	}()

	wv, err := newWebView(uiURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gui] webview 初始化失败: %v\n", err)
		return false
	}
	// API 服务启动失败也要感知
	select {
	case e := <-errCh:
		fmt.Fprintf(os.Stderr, "[gui] API 服务失败: %v\n", e)
		return false
	default:
	}
	wv.Run()
	return true
}

// fallbackBrowser 无 WebView2 时用系统默认浏览器打开 UI。
func fallbackBrowser(uiURL string, errCh chan error) {
	fmt.Fprintf(os.Stderr, "[njuConnect] WebView2 不可用，已在浏览器打开管理页: %s\n", uiURL)
	_ = openBrowser(uiURL)
	// 阻塞：API 服务报错或进程被杀
	if e := <-errCh; e != nil {
		fmt.Fprintf(os.Stderr, "[gui] API 服务退出: %v\n", e)
		os.Exit(1)
	}
	select {}
}

func fatalDialog(msg string) {
	fmt.Fprintf(os.Stderr, "[njuConnect] %s\n", msg)
	showFatalDialog(msg)
}
