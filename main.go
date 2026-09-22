package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"njuconnect/core"
	"njuconnect/gui"
	"njuconnect/proxy"
)

func newSessionWithDataDir(dataDir string) (*core.Session, string) {
	sess, err := core.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	_ = os.MkdirAll(dataDir, 0700)
	sessionFile := filepath.Join(dataDir, "session.json")
	if err := sess.Load(sessionFile); err == nil {
		log.Printf("[session] 已从 %s 恢复会话", sessionFile)
	} else if !os.IsNotExist(err) {
		log.Fatalf("无法读取现有会话 %s: %v", sessionFile, err)
	}
	return sess, sessionFile
}

func cmdLogin(cfg *core.Config) {
	sess, sessionFile := newSessionWithDataDir(cfg.DataDir)

	// 已有会话则先校验
	if info, err := sess.GetOnlineInfo(); err == nil && info.IsOnline {
		fmt.Printf("会话有效: %s (登录于 %s)\n", info.Username, info.LoginTime)
		_ = sess.Save(sessionFile)
		return
	}
	if cfg.Username == "" || cfg.Password == "" {
		log.Fatal("未提供登录凭据；请在 GUI 勾选保存密码，或配置后手动 login")
	}

	fmt.Printf("使用账号 %s 登录 (LDAP 域: %s)\n", cfg.Username, cfg.LdapDomain)
	info, err := sess.LoginLDAP(cfg.Username, cfg.Password, cfg.LdapDomain)
	if err == core.ErrSMSPending {
		// 发送验证码，保存会话，等待 verify 子命令
		if serr := sess.SendSMSCode(sess.SMSAuthId); serr != nil {
			log.Fatalf("发送短信验证码失败: %v", serr)
		}
		_ = sess.Save(sessionFile)
		fmt.Println("已触发短信验证码，请查收手机短信。")
		fmt.Printf("收到后运行: betterNJUVPN-cli verify <验证码>\n")
		os.Exit(2)
	}
	if err == core.ErrNeedSMS {
		fmt.Println("触发二次验证：请先用官方门户登录一次并绑定授信终端，或等待后续版本支持。")
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("登录失败: %v", err)
	}
	fmt.Printf("登录成功: %s (IP %s, 登录时间 %s)\n", info.Username, info.ClientIP, info.LoginTime)
	if err := sess.Save(sessionFile); err != nil {
		log.Printf("会话保存失败: %v", err)
	} else {
		fmt.Printf("会话已保存: %s\n", sessionFile)
	}
}

func cmdVerify(cfg *core.Config, code string) {
	sess, sessionFile := newSessionWithDataDir(cfg.DataDir)
	if sess.SMSAuthId == "" {
		log.Fatalf("无待验证的登录流程，请先运行 betterNJUVPN-cli login")
	}
	if err := sess.CheckSMSCode(sess.SMSAuthId, code); err != nil {
		_ = sess.Save(sessionFile) // 即便失败也保存（服务器可能已部分更新会话）
		log.Fatalf("验证码校验失败: %v", err)
	}
	// checkcode 成功 = 会话已建立，先落盘再收尾
	_ = sess.Save(sessionFile)
	info, err := sess.FinishAuth()
	if err != nil {
		_ = sess.Save(sessionFile)
		// "已在线"(75500006) 视为成功：会话有效
		if info2, err2 := sess.GetOnlineInfo(); err2 == nil && info2.IsOnline {
			info = info2
		} else {
			log.Fatalf("登录收尾失败（会话已保存）: %v", err)
		}
	}
	fmt.Printf("登录成功: %s (IP %s, 登录时间 %s)\n", info.Username, info.ClientIP, info.LoginTime)
	_ = sess.Save(sessionFile)
	fmt.Printf("会话已保存: %s\n", sessionFile)
}

// cmdProbe only uses a saved session. It never starts a new login or sends SMS.
func cmdProbe(cfg *core.Config, targets []string) error {
	sess, _ := newSessionWithDataDir(cfg.DataDir)
	info, err := sess.GetOnlineInfo()
	if err != nil || !info.IsOnline {
		return fmt.Errorf("现有会话未在线；探针不会自动登录或发送短信: %v", err)
	}
	for _, target := range targets {
		if !strings.Contains(target, "://") {
			target = "https://" + target
		}
		gwURL, err := core.RewriteTarget(target)
		if err != nil {
			fmt.Printf("%s: URL 无效: %v\n", target, err)
			continue
		}
		current := gwURL
		for hop := 0; hop < 8; hop++ {
			req, err := httpNewRequest(http.MethodGet, current)
			if err != nil {
				return err
			}
			resp, err := sess.Do(req)
			if err != nil {
				return fmt.Errorf("%s: 请求失败: %w", target, err)
			}
			loc := resp.Header.Get("Location")
			if resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
				fmt.Printf("%s: 跳转 %d %s\n", target, resp.StatusCode, resp.Request.URL.Hostname())
				resp.Body.Close()
				next, err := resp.Request.URL.Parse(loc)
				if err != nil {
					return err
				}
				current = next.String()
				continue
			}
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
			resp.Body.Close()
			if readErr != nil {
				return readErr
			}
			if m := gatewayScriptRedirectRe.FindSubmatch(body); len(m) == 2 {
				next := string(m[1])
				if u, err := url.Parse(next); err == nil && u.Scheme == "https" && ((u.Hostname() == "vpn.nju.edu.cn" && strings.HasPrefix(u.Path, "/controller/v1/public/verify")) || core.IsGatewayHost(u.Hostname())) {
					fmt.Printf("%s: 网关脚本跳转 -> %s\n", target, u.Hostname())
					current = next
					continue
				}
			}
			fmt.Printf("%s: HTTP %d; 终点 %s; 类型 %s; 长度 %d; 标题 %s\n", target, resp.StatusCode, resp.Request.URL.Hostname(), resp.Header.Get("Content-Type"), len(body), extractTitle(string(body)))
			break
		}
	}
	return nil
}

func cmdServe(cfg *core.Config) {
	sess, _ := newSessionWithDataDir(cfg.DataDir)
	if info, err := sess.GetOnlineInfo(); err != nil || !info.IsOnline {
		log.Fatal("会话未在线；serve 不自动登录。请先手动运行 login / verify 或使用 GUI 登录")
	} else {
		fmt.Printf("会话有效: %s\n", info.Username)
	}

	ca, err := proxy.LoadOrGenerateCA(cfg.DataDir)
	if err != nil {
		log.Fatalf("CA 初始化失败: %v", err)
	}
	gw := proxy.NewGateway(sess, ca, cfg.ListenProxy)
	fmt.Printf("\n使用方法:\n  1. 浏览器代理设置为 http://%s（HTTPS 也走此代理）\n", cfg.ListenProxy)
	fmt.Printf("  2. 或环境变量 HTTP_PROXY/HTTPS_PROXY=http://%s\n", cfg.ListenProxy)
	fmt.Printf("  3. 首次使用需信任 CA: %s/ca.pem\n", cfg.DataDir)
	fmt.Println("  4. 直接访问任意校内地址（如 https://lib.nju.edu.cn），代理自动改写并认证")
	if err := gw.Serve(); err != nil {
		log.Fatalf("代理退出: %v", err)
	}
}

func cmdDoctor() {
	fmt.Println("== njuconnect doctor ==")

	// 1. 公共 DNS 解析
	addrs, err := lookupHost("vpn.nju.edu.cn")
	if err != nil {
		fmt.Printf("[FAIL] 公共 DNS 解析 vpn.nju.edu.cn: %v\n", err)
	} else {
		fmt.Printf("[OK]   vpn.nju.edu.cn -> %v\n", addrs)
	}
	addrs, err = lookupHost("lib-nju-edu-cn-s.atrust.nju.edu.cn")
	if err != nil {
		fmt.Printf("[FAIL] 网关泛域名解析: %v\n", err)
	} else {
		fmt.Printf("[OK]   *.atrust.nju.edu.cn -> %v\n", addrs)
	}

	// 2. 服务端探测
	sess, _ := core.NewSession()
	cfg, err := sess.GetAuthConfig()
	if err != nil {
		fmt.Printf("[FAIL] authConfig 拉取: %v\n", err)
	} else {
		fmt.Printf("[OK]   authConfig: domains=%v pubKeyLen=%d\n", cfg.Domains, len(cfg.PubKey))
	}

	// 3. 会话状态
	if _, err := os.Stat(filepath.Join("data", "session.json")); err == nil {
		s2, f := newSessionWithDataDir("data")
		if info, err := s2.GetOnlineInfo(); err == nil && info.IsOnline {
			fmt.Printf("[OK]   本地会话有效: %s\n", info.Username)
		} else {
			fmt.Printf("[WARN] 本地会话已过期 (%s)，重新运行 login\n", f)
		}
	} else {
		fmt.Println("[WARN] 无本地会话，运行 betterNJUVPN-cli login")
	}

	// 4. 端口占用检查
	if occupied := checkPortBusy("127.0.0.1:7897"); occupied {
		fmt.Println("[WARN] 127.0.0.1:7897 被占用（应为你的 Clash，本工具默认使用 7899，无冲突）")
	}
	if checkPortBusy("127.0.0.1:7899") {
		fmt.Println("[WARN] 127.0.0.1:7899 已被占用，serve 前请释放或修改 config.json listen_proxy")
	} else {
		fmt.Println("[OK]   127.0.0.1:7899 可用")
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var gatewayScriptRedirectRe = regexp.MustCompile(`var locationUrl = "(https://[^" ]+)";`)

func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if m == nil {
		return "(无标题)"
	}
	return strings.TrimSpace(m[1])
}

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		// 双击启动：直接进入 GUI 外壳
		gui.Run()
		return
	}
	if os.Args[1] == "recover-proxy" {
		if len(os.Args) != 3 {
			log.Fatal("recover-proxy: 缺少数据目录")
		}
		if err := gui.RecoverProxy(os.Args[2]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if os.Args[1] == "recover-watch" {
		if len(os.Args) != 4 {
			log.Fatal("recover-watch: 参数错误")
		}
		pid, err := strconv.ParseUint(os.Args[2], 10, 32)
		if err != nil {
			log.Fatal(err)
		}
		if err := gui.RunProxyWatch(uint32(pid), os.Args[3]); err != nil {
			log.Fatal(err)
		}
		return
	}

	switch os.Args[1] {
	case "doctor":
		cmdDoctor()
		return
	}

	cfg, err := core.LoadConfig()
	if err != nil {
		log.Fatalf("%v", err)
	}

	switch os.Args[1] {
	case "login":
		cmdLogin(cfg)
	case "verify":
		if len(os.Args) < 3 {
			log.Fatalf("用法: betterNJUVPN-cli verify <验证码>")
		}
		cmdVerify(cfg, os.Args[2])
	case "refresh":
		sess, sessionFile := newSessionWithDataDir(cfg.DataDir)
		info, err := sess.RefreshSession()
		if err != nil {
			log.Fatalf("会话恢复失败: %v", err)
		}
		fmt.Printf("会话恢复成功: %s (IP %s, 登录时间 %s)\n", info.Username, info.ClientIP, info.LoginTime)
		_ = sess.Save(sessionFile)
	case "serve":
		cmdServe(cfg)
	case "probe", "test":
		if len(os.Args) < 3 {
			log.Fatal("用法: njuconnect probe <URL> [URL...]")
		}
		if err := cmdProbe(cfg, os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`betterNJUVPN — 南京大学 aTrust VPN 免客户端接入工具

无参数启动 = GUI 窗口（推荐双击运行）

用法:
  njuconnect-cli login          登录并保存会话
  njuconnect-cli serve          启动本地代理（默认 127.0.0.1:7899，避开 Clash 7897）
  njuconnect-cli probe <URL>... 仅使用现有会话检查站点，不触发登录或短信
  njuconnect-cli doctor         诊断 DNS/服务端/会话/端口

配置文件 config.json 示例见 config.example.json（含明文凭据，切勿提交或分享）`)
	_ = flag.CommandLine
}
