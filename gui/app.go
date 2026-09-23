package gui

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"njuconnect/core"
	"njuconnect/proxy"
)

// App GUI 外壳的应用状态机：
//   idle -> logging_in -> (sms_pending <-> submitting_sms) -> online(+proxy) -> ...
// 单线程状态变更（mu 保护），长任务在 goroutine 中推进。

type State string

const (
	StateIdle       State = "idle"
	StateLoggingIn  State = "logging_in"
	StateSMSPending State = "sms_pending"
	StateSubmitting State = "submitting_sms"
	StateOnline     State = "online"
	StateError      State = "error"
)

type App struct {
	mu            sync.Mutex
	authMu        sync.Mutex // Serializes login, SMS and logout, including background work.
	state         State
	message       string // 给 UI 的提示（含错误）
	phoneMasked   string // 短信弹窗展示的掩码手机号
	lastSMS       time.Time
	proxyAddr     string // "127.0.0.1:7899"
	proxyOn       bool
	proxyMode     string
	systemProxyOn bool
	username      string // 掩码后的账号展示
	cfg           *core.Config
	sess          *core.Session
	sessionFile   string
	gateway       *proxy.Gateway
	server        *http.Server
	systemProxy   *systemProxyManager
	tun           *tunManager
	tunBusy       bool
	traffic       trafficCounters
	caTrusted     bool
}

func NewApp(cfg *core.Config) (*App, error) {
	manager := newSystemProxyManager(cfg.DataDir)
	if err := manager.Restore(); err != nil {
		return nil, fmt.Errorf("恢复上次系统代理设置失败: %w", err)
	}
	if err := manager.ClearStaleOwnProxy(cfg.ListenProxy); err != nil {
		return nil, fmt.Errorf("清理失效代理设置失败: %w", err)
	}
	a := &App{state: StateIdle, cfg: cfg, proxyAddr: cfg.ListenProxy, proxyMode: cfg.ProxyMode, systemProxyOn: cfg.SystemProxy == "on", systemProxy: manager, tun: newTunManager()}
	a.username = maskUser(cfg.Username)
	_ = os.MkdirAll(cfg.DataDir, 0700)
	a.sessionFile = filepath.Join(cfg.DataDir, "session.json")
	a.caTrusted = localCATrusted(cfg.DataDir)
	return a, nil
}

func maskUser(u string) string {
	if len(u) >= 6 {
		return u[:3] + "****" + u[len(u)-3:]
	}
	return u
}

func (a *App) snapshot() map[string]interface{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	return map[string]interface{}{
		"state":            string(a.state),
		"message":          a.message,
		"phone":            a.phoneMasked,
		"proxyAddr":        a.proxyAddr,
		"proxyOn":          a.proxyOn,
		"tunOn":            a.tun.Running(),
		"tunBusy":          a.tunBusy,
		"tunAvailable":     tunIsElevated(),
		"proxyMode":        a.proxyMode,
		"systemProxyOn":    a.systemProxyOn,
		"username":         a.username,
		"loginUsername":    a.cfg.Username,
		"rememberPassword": a.cfg.RememberPassword,
		"hasPassword":      a.cfg.RememberPassword && a.cfg.Password != "",
		"uploadBytes":      a.traffic.upload.Load(),
		"downloadBytes":    a.traffic.download.Load(),
		"caTrusted":        a.caTrusted,
	}
}

// ---- 登录状态机 ----

func (a *App) setState(s State, msg string) {
	a.mu.Lock()
	a.state, a.message = s, msg
	a.mu.Unlock()
}

// StartLogin 异步登录：恢复会话 -> 在线即启动代理；否则走密码登录，需要短信则弹窗。
func (a *App) StartLogin(username, password string, remember, auto bool) error {
	if !a.authMu.TryLock() {
		return fmt.Errorf("登录操作正在进行，请稍候")
	}
	a.mu.Lock()
	if a.state == StateOnline || a.state == StateSMSPending || a.state == StateSubmitting || a.state == StateLoggingIn {
		a.mu.Unlock()
		a.authMu.Unlock()
		return fmt.Errorf("当前状态不能重复登录")
	}
	if username != "" && username != a.cfg.Username {
		a.cfg.Username = username
		a.cfg.Password = ""
	}
	if password != "" {
		a.cfg.Password = password
	}
	if !auto {
		a.cfg.RememberPassword = remember
		if err := a.cfg.Save(); err != nil {
			a.mu.Unlock()
			a.authMu.Unlock()
			return fmt.Errorf("保存设置失败: %w", err)
		}
	}
	cfg := *a.cfg
	a.state, a.message = StateLoggingIn, "正在连接学校服务器…"
	a.mu.Unlock()
	go func() {
		defer a.authMu.Unlock()
		sess, err := core.NewSession()
		if err != nil {
			a.setState(StateError, "初始化失败: "+err.Error())
			return
		}
		a.mu.Lock()
		a.sess = sess
		a.mu.Unlock()
		if err := loadLoginSession(sess, a.sessionFile, auto); err != nil {
			a.setState(StateError, "无法读取现有会话: "+err.Error())
			return
		}

		// 1) 已有会话直接复用
		if info, ierr := sess.GetOnlineInfo(); ierr == nil && info.IsOnline {
			a.finishLogin(sess, info)
			return
		}
		if auto {
			a.setState(StateIdle, "会话未在线，请手动登录")
			return
		}
		if cfg.Username == "" || cfg.Password == "" {
			a.setState(StateError, "请先填写学号和密码")
			return
		}

		// 2) 密码登录（内部带 x-sdp-env 设备标识与 CSRF 轮换）
		info, err := sess.LoginLDAP(cfg.Username, cfg.Password, cfg.LdapDomain)
		switch err {
		case nil:
			_ = sess.Save(a.sessionFile)
			a.finishLogin(sess, info)
			return
		case core.ErrSMSPending:
			// 3) 短信二次验证：触发发送并弹出验证码窗口
			phone := sess.GetMaskedPhone(sess.SMSAuthId)
			a.mu.Lock()
			a.phoneMasked = phone
			a.mu.Unlock()
			_ = sess.Save(a.sessionFile)
			if serr := sess.SendSMSCode(sess.SMSAuthId); serr != nil {
				a.setState(StateError, "发送验证码失败: "+serr.Error())
				return
			}
			a.mu.Lock()
			a.lastSMS = time.Now()
			a.mu.Unlock()
			_ = sess.Save(a.sessionFile)
			a.setState(StateSMSPending, "学校网关已接受发送请求；若手机未收到，请核对号码后重发")
			return
		default:
			a.setState(StateError, "登录失败: "+err.Error())
			return
		}
	}()
	return nil
}

// SubmitSMS 异步提交短信验证码。
func (a *App) SubmitSMS(code string) error {
	if !a.authMu.TryLock() {
		return fmt.Errorf("登录操作正在进行，请稍候")
	}
	a.mu.Lock()
	sess := a.sess
	if a.state != StateSMSPending || sess == nil || sess.SMSAuthId == "" {
		a.mu.Unlock()
		a.authMu.Unlock()
		return fmt.Errorf("无待校验的登录，请重新登录")
	}
	a.state, a.message = StateSubmitting, "正在校验验证码…"
	a.mu.Unlock()
	go func() {
		defer a.authMu.Unlock()
		if err := sess.CheckSMSCode(sess.SMSAuthId, code); err != nil {
			a.setState(StateSMSPending, "验证码校验失败: "+err.Error())
			return
		}
		_ = sess.Save(a.sessionFile) // checkcode 响应里的会话 Cookie 只下发一次
		info, err := sess.FinishAuth()
		if err != nil {
			if info2, e2 := sess.GetOnlineInfo(); e2 == nil && info2.IsOnline {
				info = info2
			} else {
				_ = sess.Save(a.sessionFile)
				a.setState(StateError, "登录收尾失败: "+err.Error())
				return
			}
		}
		_ = sess.Save(a.sessionFile)
		a.finishLogin(sess, info)
	}()
	return nil
}

// ResendSMS 仅在等待短信时允许手动重发，避免误点造成频繁发送。
func (a *App) ResendSMS() error {
	if !a.authMu.TryLock() {
		return fmt.Errorf("登录操作正在进行，请稍候")
	}
	defer a.authMu.Unlock()
	a.mu.Lock()
	if a.state != StateSMSPending || a.sess == nil || a.sess.SMSAuthId == "" {
		a.mu.Unlock()
		return fmt.Errorf("当前没有等待验证的短信")
	}
	if remaining := 60*time.Second - time.Since(a.lastSMS); remaining > 0 {
		a.mu.Unlock()
		return fmt.Errorf("请 %d 秒后重发", int(remaining.Seconds())+1)
	}
	sess := a.sess
	a.lastSMS = time.Now()
	a.mu.Unlock()
	if err := sess.SendSMSCode(sess.SMSAuthId); err != nil {
		a.setState(StateSMSPending, "重发请求失败: "+err.Error())
		return err
	}
	a.setState(StateSMSPending, "学校网关已接受重发请求；请查看绑定手机")
	return nil
}

func (a *App) finishLogin(sess *core.Session, info *core.OnlineInfo) {
	a.mu.Lock()
	a.username = maskUser(info.Username)
	start := a.systemProxyOn
	a.mu.Unlock()
	a.setState(StateOnline, "")
	if start {
		if err := a.startProxy(); err != nil {
			a.setState(StateOnline, "代理启动失败: "+err.Error())
		}
	}
}

// ---- 代理 ----

func (a *App) startProxy() error {
	a.mu.Lock()
	if a.proxyOn {
		a.mu.Unlock()
		return nil
	}
	conflicts := otherProxyApps(a.cfg.ListenProxy)
	sess := a.sess
	if sess == nil {
		a.mu.Unlock()
		return fmt.Errorf("会话未就绪")
	}
	ln, err := net.Listen("tcp", a.cfg.ListenProxy)
	if err != nil {
		a.mu.Unlock()
		return fmt.Errorf("端口 %s 不可用: %w", a.cfg.ListenProxy, err)
	}
	ca, err := proxy.LoadOrGenerateCA(a.cfg.DataDir)
	if err != nil {
		ln.Close()
		a.mu.Unlock()
		return fmt.Errorf("CA 初始化失败: %w", err)
	}
	a.caTrusted = localCATrusted(a.cfg.DataDir)
	gw := proxy.NewGateway(sess, ca, a.cfg.ListenProxy)
	if a.systemProxyOn && !a.tun.Running() {
		if err := a.systemProxy.Enable(a.cfg.ListenProxy, a.proxyMode); err != nil {
			ln.Close()
			a.mu.Unlock()
			return fmt.Errorf("系统代理设置失败: %w", err)
		}
		if a.proxyMode != "direct" {
			if err := StartProxyWatch(a.cfg.DataDir); err != nil {
				_ = a.systemProxy.Restore()
				ln.Close()
				a.mu.Unlock()
				return fmt.Errorf("启动代理恢复监护失败: %w", err)
			}
		}
	}
	srv := &http.Server{Handler: gw}
	a.gateway = gw
	a.server = srv
	a.proxyOn = true
	a.message = "代理运行中"
	if len(conflicts) > 0 {
		a.message = "检测到其他代理应用运行（" + strings.Join(conflicts, "、") + "），可能造成异常卡顿"
	}
	a.mu.Unlock()
	go func() {
		if serr := srv.Serve(trafficListener{Listener: ln, counters: &a.traffic}); serr != nil && serr != http.ErrServerClosed {
			_ = a.StopProxy()
			a.setState(StateOnline, "代理退出: "+serr.Error())
		}
	}()
	log.Printf("[gui] 代理已启动 %s", a.cfg.ListenProxy)
	return nil
}

func (a *App) StopProxy() error {
	tunErr := a.tun.Stop()
	a.mu.Lock()
	srv, gw := a.server, a.gateway
	a.server, a.gateway = nil, nil
	a.proxyOn = false
	a.mu.Unlock()
	err := a.systemProxy.Restore()
	if err == nil {
		err = tunErr
	}
	if gw != nil {
		gw.Close()
	}
	if srv != nil {
		_ = srv.Close()
	}
	a.mu.Lock()
	if err != nil {
		a.message = "恢复系统代理失败: " + err.Error()
	} else {
		a.message = "代理已暂停，系统代理已恢复"
	}
	a.mu.Unlock()
	return err
}

func (a *App) StartTUN() error {
	a.mu.Lock()
	if a.state != StateOnline {
		a.mu.Unlock()
		return fmt.Errorf("请先登录")
	}
	startProxy := !a.proxyOn
	addr, dataDir, systemOn, mode := a.cfg.ListenProxy, a.cfg.DataDir, a.systemProxyOn, a.proxyMode
	a.mu.Unlock()
	if startProxy {
		if err := a.startProxy(); err != nil {
			return err
		}
	}
	if a.tun.Running() {
		return nil
	}
	if err := a.systemProxy.Restore(); err != nil {
		return err
	}
	if err := a.tun.Start(dataDir, addr); err != nil {
		if systemOn {
			if a.systemProxy.Enable(addr, mode) == nil && mode != "direct" {
				_ = StartProxyWatch(dataDir)
			}
		}
		return err
	}
	a.mu.Lock()
	a.message = "虚拟网卡运行中：南大网页经本地代理，其余流量直连"
	if conflicts := otherProxyApps(addr); len(conflicts) > 0 {
		a.message += "；检测到其他代理应用运行（" + strings.Join(conflicts, "、") + "），可能造成异常卡顿"
	}
	a.mu.Unlock()
	return nil
}

func (a *App) StopTUN() error {
	err := a.tun.Stop()
	a.mu.Lock()
	proxyOn, systemOn, mode, addr := a.proxyOn, a.systemProxyOn, a.proxyMode, a.cfg.ListenProxy
	a.mu.Unlock()
	if proxyOn && systemOn {
		if restoreErr := a.systemProxy.Enable(addr, mode); err == nil {
			err = restoreErr
		}
		if err == nil && mode != "direct" {
			if watchErr := StartProxyWatch(a.cfg.DataDir); watchErr != nil {
				_ = a.systemProxy.Restore()
				err = watchErr
			}
		}
	}
	if err == nil {
		a.mu.Lock()
		a.message = "虚拟网卡已关闭"
		a.mu.Unlock()
		if !systemOn && proxyOn {
			return a.StopProxy()
		}
	}
	return err
}

func (a *App) UpdateSettings(port int, systemOn bool, mode string) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("端口必须在 1-65535 之间")
	}
	if mode != "rule" && mode != "global" && mode != "direct" {
		return fmt.Errorf("未知代理模式")
	}
	newAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	a.mu.Lock()
	if a.tun.Running() {
		a.mu.Unlock()
		return fmt.Errorf("请先关闭虚拟网卡，再修改设置")
	}
	restart := a.proxyOn && (!systemOn || newAddr != a.cfg.ListenProxy)
	a.mu.Unlock()
	if restart {
		if err := a.StopProxy(); err != nil {
			return err
		}
	}
	a.mu.Lock()
	if a.proxyOn && (systemOn != a.systemProxyOn || mode != a.proxyMode) {
		var err error
		if systemOn {
			err = a.systemProxy.Enable(newAddr, mode)
		} else {
			err = a.systemProxy.Restore()
		}
		if err != nil {
			a.mu.Unlock()
			return err
		}
		if systemOn && mode != "direct" {
			if err := StartProxyWatch(a.cfg.DataDir); err != nil {
				_ = a.systemProxy.Restore()
				a.mu.Unlock()
				return err
			}
		}
	}
	old := *a.cfg
	a.cfg.ListenProxy = newAddr
	a.cfg.ProxyMode = mode
	if systemOn {
		a.cfg.SystemProxy = "on"
	} else {
		a.cfg.SystemProxy = "off"
	}
	if err := a.cfg.Save(); err != nil {
		*a.cfg = old
		a.mu.Unlock()
		return err
	}
	a.proxyAddr = a.cfg.ListenProxy
	a.proxyMode = mode
	a.systemProxyOn = systemOn
	a.message = "设置已保存"
	shouldStart := systemOn && a.state == StateOnline && !a.proxyOn
	a.mu.Unlock()
	if shouldStart {
		return a.startProxy()
	}
	return nil
}

func (a *App) Logout() error {
	if !a.authMu.TryLock() {
		return fmt.Errorf("登录操作正在进行，请稍候再退出登录")
	}
	defer a.authMu.Unlock()
	if err := a.StopProxy(); err != nil {
		return err
	}
	a.mu.Lock()
	a.sess = nil
	a.state = StateIdle
	a.message = "已退出登录"
	a.username = ""
	a.cfg.Password = ""
	a.cfg.RememberPassword = false
	defer a.mu.Unlock()
	if err := os.Remove(a.sessionFile); err != nil && !os.IsNotExist(err) {
		return err
	}
	return a.cfg.Save()
}

// ---- HTTP API（WebView/浏览器与后端的桥） ----

func (a *App) ServeAPI(ln net.Listener, mux *http.ServeMux) error {
	mux.HandleFunc("/api/proxy/conflicts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		a.mu.Lock()
		addr := a.proxyAddr
		a.mu.Unlock()
		writeJSON(w, map[string]interface{}{"apps": otherProxyApps(addr)})
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.snapshot())
	})
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if !apiWriteAllowed(w, r) {
			return
		}
		var req struct {
			Username, Password     string
			RememberPassword, Auto bool
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := a.StartLogin(req.Username, req.Password, req.RememberPassword, req.Auto); err != nil {
			w.WriteHeader(http.StatusConflict)
			writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/sms", func(w http.ResponseWriter, r *http.Request) {
		if !apiWriteAllowed(w, r) {
			return
		}
		var req struct{ Code string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := a.SubmitSMS(req.Code); err != nil {
			w.WriteHeader(http.StatusConflict)
			writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/sms/resend", func(w http.ResponseWriter, r *http.Request) {
		if !apiWriteAllowed(w, r) {
			return
		}
		if err := a.ResendSMS(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/proxy", func(w http.ResponseWriter, r *http.Request) {
		if !apiWriteAllowed(w, r) {
			return
		}
		var req struct{ Action string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		var err error
		if req.Action == "start" {
			a.mu.Lock()
			on := a.proxyOn
			sess := a.sess
			state := a.state
			a.mu.Unlock()
			if state != StateOnline || sess == nil {
				err = fmt.Errorf("请先完成登录")
			} else if !on {
				err = a.startProxy()
			}
		} else if req.Action == "stop" {
			err = a.StopProxy()
		} else {
			err = fmt.Errorf("未知代理操作")
		}
		if err != nil {
			a.mu.Lock()
			a.message = err.Error()
			a.mu.Unlock()
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/tun", func(w http.ResponseWriter, r *http.Request) {
		if !apiWriteAllowed(w, r) {
			return
		}
		var req struct{ Action string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if req.Action != "start" && req.Action != "stop" {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]interface{}{"ok": false, "error": "未知虚拟网卡操作"})
			return
		}
		a.mu.Lock()
		if a.tunBusy {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			writeJSON(w, map[string]interface{}{"ok": false, "error": "虚拟网卡操作正在进行"})
			return
		}
		a.tunBusy = true
		a.message = "正在" + map[bool]string{true: "开启", false: "关闭"}[req.Action == "start"] + "虚拟网卡…"
		a.mu.Unlock()
		go func() {
			var err error
			if req.Action == "start" {
				err = a.StartTUN()
			} else {
				err = a.StopTUN()
			}
			a.mu.Lock()
			if err != nil {
				a.message = "虚拟网卡操作失败: " + err.Error()
			}
			a.tunBusy = false
			a.mu.Unlock()
		}()
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		if !apiWriteAllowed(w, r) {
			return
		}
		var req struct {
			Port          int
			SystemProxyOn bool
			ProxyMode     string
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := a.UpdateSettings(req.Port, req.SystemProxyOn, req.ProxyMode); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/ca/trust", func(w http.ResponseWriter, r *http.Request) {
		if !apiWriteAllowed(w, r) {
			return
		}
		a.mu.Lock()
		dataDir := a.cfg.DataDir
		a.mu.Unlock()
		if err := TrustLocalCA(dataDir); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		a.mu.Lock()
		a.caTrusted = true
		a.message = "本地证书已受当前用户信任，请刷新校园网页"
		a.mu.Unlock()
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		if !apiWriteAllowed(w, r) {
			return
		}
		if err := a.Logout(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/quit", func(w http.ResponseWriter, r *http.Request) {
		if !apiWriteAllowed(w, r) {
			return
		}
		if err := a.StopProxy(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
		go func() {
			time.Sleep(300 * time.Millisecond)
			os.Exit(0)
		}()
	})
	srv := &http.Server{Handler: mux}
	return srv.Serve(ln)
}

func apiWriteAllowed(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return false
	}
	origin, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || origin.Scheme != "http" || origin.Host != r.Host || origin.Path != "" {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
