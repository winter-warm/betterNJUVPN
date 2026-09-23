//go:build windows

package gui

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
	"njuconnect/core"
)

const internetSettings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
const proxyRunOnceKey = `Software\Microsoft\Windows\CurrentVersion\RunOnce`
const proxyRunOnceName = "njuConnectProxyRestore"

type proxyString struct {
	Present bool   `json:"present"`
	Value   string `json:"value"`
}
type proxyDword struct {
	Present bool   `json:"present"`
	Value   uint64 `json:"value"`
}
type winProxyValues struct {
	Enable     proxyDword  `json:"enable"`
	Server     proxyString `json:"server"`
	Override   proxyString `json:"override"`
	AutoConfig proxyString `json:"auto_config"`
	AutoDetect proxyDword  `json:"auto_detect"`
}
type proxyRecovery struct {
	Previous winProxyValues `json:"previous"`
	Applied  winProxyValues `json:"applied"`
}

type systemProxyManager struct{ stateFile string }

func newSystemProxyManager(dataDir string) *systemProxyManager {
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		abs = dataDir
	}
	return &systemProxyManager{stateFile: filepath.Join(abs, "system-proxy-state.json")}
}

func (m *systemProxyManager) registerRunOnce() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, proxyRunOnceKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	cmd := `"` + exe + `" recover-proxy "` + filepath.Dir(m.stateFile) + `"`
	return k.SetStringValue(proxyRunOnceName, cmd)
}

func (m *systemProxyManager) removeRunOnce() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, proxyRunOnceKey, registry.SET_VALUE)
	if err == registry.ErrNotExist {
		return nil
	}
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(proxyRunOnceName); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}

func readProxyValues(k registry.Key) (winProxyValues, error) {
	var v winProxyValues
	var err error
	if v.Enable, err = readDword(k, "ProxyEnable"); err != nil {
		return v, err
	}
	if v.Server, err = readString(k, "ProxyServer"); err != nil {
		return v, err
	}
	if v.Override, err = readString(k, "ProxyOverride"); err != nil {
		return v, err
	}
	if v.AutoConfig, err = readString(k, "AutoConfigURL"); err != nil {
		return v, err
	}
	if v.AutoDetect, err = readDword(k, "AutoDetect"); err != nil {
		return v, err
	}
	return v, nil
}

func readString(k registry.Key, name string) (proxyString, error) {
	v, _, err := k.GetStringValue(name)
	if err == registry.ErrNotExist {
		return proxyString{}, nil
	}
	if err != nil {
		return proxyString{}, err
	}
	return proxyString{true, v}, nil
}

func readDword(k registry.Key, name string) (proxyDword, error) {
	v, _, err := k.GetIntegerValue(name)
	if err == registry.ErrNotExist {
		return proxyDword{}, nil
	}
	if err != nil {
		return proxyDword{}, err
	}
	return proxyDword{true, v}, nil
}

func writeProxyValues(k registry.Key, v winProxyValues) error {
	for _, field := range []struct {
		name  string
		value proxyString
	}{
		{"ProxyServer", v.Server}, {"ProxyOverride", v.Override}, {"AutoConfigURL", v.AutoConfig},
	} {
		var err error
		if field.value.Present {
			err = k.SetStringValue(field.name, field.value.Value)
		} else {
			err = k.DeleteValue(field.name)
			if err == registry.ErrNotExist {
				err = nil
			}
		}
		if err != nil {
			return err
		}
	}
	for _, field := range []struct {
		name  string
		value proxyDword
	}{
		{"ProxyEnable", v.Enable}, {"AutoDetect", v.AutoDetect},
	} {
		var err error
		if field.value.Present {
			err = k.SetDWordValue(field.name, uint32(field.value.Value))
		} else {
			err = k.DeleteValue(field.name)
			if err == registry.ErrNotExist {
				err = nil
			}
		}
		if err != nil {
			return err
		}
	}
	return notifyProxyChange()
}

func notifyProxyChange() error {
	proc := syscall.NewLazyDLL("wininet.dll").NewProc("InternetSetOptionW")
	for _, option := range []uintptr{39, 37} { // SETTINGS_CHANGED, REFRESH
		r, _, e := proc.Call(0, option, 0, 0)
		if r == 0 {
			return fmt.Errorf("更新 Windows 代理设置失败: %v", e)
		}
	}
	return nil
}

func usesLocalProxy(v winProxyValues, addr string) bool {
	return v.AutoConfig.Present && v.AutoConfig.Value == "http://"+addr+"/proxy.pac" ||
		v.Enable.Present && v.Enable.Value != 0 && v.Server.Present && v.Server.Value == addr
}

func withoutProxy(v winProxyValues) winProxyValues {
	v.Enable = proxyDword{true, 0}
	v.Server = proxyString{}
	v.AutoConfig = proxyString{}
	return v
}

// restoreOwnedValues restores fields still carrying this app's applied values.
// Windows may change an unrelated value (notably AutoDetect) while the PAC is
// active; that must not leave our endpoint behind or overwrite a later change.
func restoreOwnedValues(current winProxyValues, recovery proxyRecovery) (winProxyValues, bool) {
	addr := recovery.Applied.Server.Value
	if recovery.Applied.AutoConfig.Present {
		addr = strings.TrimSuffix(strings.TrimPrefix(recovery.Applied.AutoConfig.Value, "http://"), "/proxy.pac")
	}
	if !usesLocalProxy(current, addr) {
		return current, false
	}
	merged := current
	if current.Enable == recovery.Applied.Enable {
		merged.Enable = recovery.Previous.Enable
	}
	if current.Server == recovery.Applied.Server {
		merged.Server = recovery.Previous.Server
	}
	if current.Override == recovery.Applied.Override {
		merged.Override = recovery.Previous.Override
	}
	if current.AutoConfig == recovery.Applied.AutoConfig {
		merged.AutoConfig = recovery.Previous.AutoConfig
	}
	if current.AutoDetect == recovery.Applied.AutoDetect {
		merged.AutoDetect = recovery.Previous.AutoDetect
	}
	if usesLocalProxy(merged, addr) {
		merged = withoutProxy(merged)
	}
	return merged, true
}

// ClearStaleOwnProxy handles older runs that left an app endpoint in Windows
// settings without a recovery file. It only acts when that endpoint is down.
func (m *systemProxyManager) ClearStaleOwnProxy(addr string) error {
	if _, err := os.Stat(m.stateFile); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		return nil
	}
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		return nil
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	current, err := readProxyValues(k)
	if err != nil {
		return err
	}
	if usesLocalProxy(current, addr) {
		return writeProxyValues(k, withoutProxy(current))
	}
	return nil
}

func ClearStaleOwnProxy(dataDir, addr string) error {
	return newSystemProxyManager(dataDir).ClearStaleOwnProxy(addr)
}

func (m *systemProxyManager) Enable(addr, mode string) error {
	if mode == "direct" {
		return m.Restore()
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return err
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	previous, err := readProxyValues(k)
	if err != nil {
		return err
	}
	if data, err := os.ReadFile(m.stateFile); err == nil {
		var recovery proxyRecovery
		if err := json.Unmarshal(data, &recovery); err != nil {
			return err
		}
		if restored, owned := restoreOwnedValues(previous, recovery); owned {
			previous = restored
		} else {
			// Another program changed the proxy; preserve its current settings.
			if err := m.removeRunOnce(); err != nil {
				return err
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if usesLocalProxy(previous, addr) {
		previous = withoutProxy(previous)
	}
	applied := previous
	applied.AutoDetect = proxyDword{true, 0}
	applied.Override = proxyString{true, "<local>;localhost;127.*"}
	if mode == "rule" {
		applied.Enable = proxyDword{true, 0}
		applied.Server = proxyString{}
		applied.AutoConfig = proxyString{true, "http://" + addr + "/proxy.pac"}
	} else if mode == "global" {
		applied.Enable = proxyDword{true, 1}
		applied.Server = proxyString{true, addr}
		applied.AutoConfig = proxyString{}
	} else {
		return fmt.Errorf("未知代理模式: %s", mode)
	}
	if err := os.MkdirAll(filepath.Dir(m.stateFile), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(proxyRecovery{Previous: previous, Applied: applied})
	if err != nil {
		return err
	}
	if err := os.WriteFile(m.stateFile, data, 0600); err != nil {
		return err
	}
	if err := core.SecureFile(m.stateFile); err != nil {
		return err
	}
	if err := m.registerRunOnce(); err != nil {
		_ = os.Remove(m.stateFile)
		return err
	}
	if err := writeProxyValues(k, applied); err != nil {
		_ = writeProxyValues(k, previous)
		_ = os.Remove(m.stateFile)
		_ = m.removeRunOnce()
		return err
	}
	return nil
}

// Restore changes Windows settings only while they still match what this app
// applied. Another proxy app may take ownership while njuConnect is open.
func (m *systemProxyManager) Restore() error {
	data, err := os.ReadFile(m.stateFile)
	if os.IsNotExist(err) {
		return m.removeRunOnce()
	}
	if err != nil {
		return err
	}
	var recovery proxyRecovery
	if err := json.Unmarshal(data, &recovery); err != nil {
		return err
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	current, err := readProxyValues(k)
	if err != nil {
		return err
	}
	if restored, owned := restoreOwnedValues(current, recovery); owned {
		if err := writeProxyValues(k, restored); err != nil {
			return err
		}
	}
	if err := os.Remove(m.stateFile); err != nil {
		return err
	}
	return m.removeRunOnce()
}
