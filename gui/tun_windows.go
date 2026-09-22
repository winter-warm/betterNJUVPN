//go:build windows

package gui

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"njuconnect/core"
)

// tunManager owns only the njuConnect Mihomo process. It never opens Clash's
// configuration, controller or adapter. NJU Web traffic uses the local proxy;
// all other traffic is handled by the DIRECT rule.
type tunManager struct {
	mu         sync.Mutex
	cmd        *exec.Cmd
	controller string
	secret     string
	logFile    *os.File
	done       chan struct{}
	job        windows.Handle
}

func newTunManager() *tunManager { return &tunManager{} }
func tunIsElevated() bool        { return windows.GetCurrentProcessToken().IsElevated() }

func tunBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	path := filepath.Join(filepath.Dir(exe), "tools", "mihomo", "mihomo-windows-amd64-compatible.exe")
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("未找到独立 Mihomo 核心 %s", path)
	}
	return path, nil
}

func tunConfig(proxyPort, controllerPort int, secret string) string {
	return fmt.Sprintf(`mode: rule
log-level: info
allow-lan: false
ipv6: true
external-controller: 127.0.0.1:%d
secret: %s
profile:
  store-selected: false
  store-fake-ip: false
dns:
  enable: true
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.19.0.1/16
  nameserver:
    - 223.5.5.5
tun:
  enable: true
  stack: gvisor
  device: njuConnectTun
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
    - tcp://any:53
  route-address:
    - 0.0.0.0/1
    - 128.0.0.0/1
    - ::/1
    - 8000::/1
  strict-route: false
sniffer:
  enable: true
  parse-pure-ip: true
  override-destination: true
  sniff:
    HTTP:
      ports: [80]
    TLS:
      ports: [443]
proxies:
  - name: NJU-Web
    type: http
    server: 127.0.0.1
    port: %d
rules:
  - DOMAIN-SUFFIX,nju.edu.cn,NJU-Web
  - MATCH,DIRECT
`, controllerPort, secret, proxyPort)
}

func (m *tunManager) Start(dataDir, proxyAddr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil {
		select {
		case <-m.done:
			m.logFile.Close()
			if m.job != 0 {
				windows.CloseHandle(m.job)
			}
			m.cmd, m.controller, m.secret, m.logFile, m.done, m.job = nil, "", "", nil, nil, 0
		default:
			return nil
		}
	}
	if !tunIsElevated() {
		return fmt.Errorf("虚拟网卡需要以管理员身份启动 njuConnect")
	}
	bin, err := tunBinary()
	if err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return err
	}
	proxyPort, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	ctlPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return err
	}
	secret := hex.EncodeToString(secretBytes)
	dir := filepath.Join(dataDir, "tun")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	config := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(config, []byte(tunConfig(proxyPort, ctlPort, secret)), 0600); err != nil {
		return err
	}
	if err := core.SecureFile(config); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(dir, "mihomo.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := core.SecureFile(logFile.Name()); err != nil {
		logFile.Close()
		return err
	}
	cmd := exec.Command(bin, "-d", dir, "-f", config)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		logFile.Close()
		return err
	}
	var jobInfo windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	jobInfo.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&jobInfo)), uint32(unsafe.Sizeof(jobInfo))); err != nil {
		windows.CloseHandle(job)
		logFile.Close()
		return err
	}
	if err := cmd.Start(); err != nil {
		windows.CloseHandle(job)
		logFile.Close()
		return err
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, process)
		windows.CloseHandle(process)
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		windows.CloseHandle(job)
		logFile.Close()
		return fmt.Errorf("无法绑定 TUN 子进程到自动回收任务: %w", err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	controller := fmt.Sprintf("http://127.0.0.1:%d", ctlPort)
	client := &http.Client{Timeout: time.Second}
	for i := 0; i < 50; i++ {
		select {
		case <-done:
			windows.CloseHandle(job)
			logFile.Close()
			return fmt.Errorf("Mihomo 提前退出，请查看 %s", logFile.Name())
		default:
		}
		req, _ := http.NewRequest(http.MethodGet, controller+"/configs", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
			resp.Body.Close()
			var status struct {
				Tun struct {
					Enable bool `json:"enable"`
				} `json:"tun"`
			}
			_ = json.Unmarshal(body, &status)
			adapter, adapterErr := net.InterfaceByName("njuConnectTun")
			if resp.StatusCode == http.StatusOK && status.Tun.Enable && adapterErr == nil && adapter.Flags&net.FlagUp != 0 {
				m.cmd, m.controller, m.secret, m.logFile, m.done, m.job = cmd, controller, secret, logFile, done, job
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	<-done
	windows.CloseHandle(job)
	logFile.Close()
	return fmt.Errorf("Mihomo TUN 启动超时，请查看 %s", logFile.Name())
}

func (m *tunManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd == nil {
		return nil
	}
	client := &http.Client{Timeout: 3 * time.Second}
	req, _ := http.NewRequest(http.MethodPatch, m.controller+"/configs", strings.NewReader(`{"tun":{"enable":false}}`))
	req.Header.Set("Authorization", "Bearer "+m.secret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if err == nil && resp.StatusCode != http.StatusNoContent {
		err = fmt.Errorf("Mihomo 关闭 TUN 返回 HTTP %d", resp.StatusCode)
	}
	if err == nil {
		time.Sleep(300 * time.Millisecond)
	}
	_ = m.cmd.Process.Kill()
	select {
	case <-m.done:
	case <-time.After(3 * time.Second):
	}
	m.logFile.Close()
	if m.job != 0 {
		windows.CloseHandle(m.job)
	}
	m.cmd, m.controller, m.secret, m.logFile, m.done, m.job = nil, "", "", nil, nil, 0
	return err
}

func (m *tunManager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd == nil {
		return false
	}
	select {
	case <-m.done:
		return false
	default:
		return true
	}
}
