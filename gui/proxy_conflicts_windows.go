//go:build windows

package gui

import (
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var proxyProcessNames = map[string]string{
	"clash.exe": "Clash", "clash-verge.exe": "Clash Verge", "clash-verge-rev.exe": "Clash Verge Rev",
	"clash for windows.exe": "Clash for Windows", "verge-mihomo.exe": "Clash Verge",
	"mihomo.exe": "Mihomo", "v2rayn.exe": "v2rayN", "xray.exe": "Xray",
	"sing-box.exe": "sing-box", "nekoray.exe": "Nekoray", "nekobox.exe": "NekoBox",
	"shadowsocks.exe": "Shadowsocks", "shadowsocksr-dotnet4.0.exe": "ShadowsocksR",
	"flclash.exe": "FlClash", "hiddify.exe": "Hiddify", "proxifier.exe": "Proxifier",
}

// otherProxyApps only reads process and current-user proxy state. It does not
// change another application's processes or settings.
func otherProxyApps(ownAddr string) []string {
	found := make(map[string]bool)
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err == nil {
		defer windows.CloseHandle(snapshot)
		var entry windows.ProcessEntry32
		entry.Size = uint32(unsafe.Sizeof(entry))
		if windows.Process32First(snapshot, &entry) == nil {
			for {
				if name := proxyProcessNames[strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))]; name != "" {
					found[name] = true
				}
				if windows.Process32Next(snapshot, &entry) != nil {
					break
				}
			}
		}
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		if values, err := readProxyValues(k); err == nil && !usesLocalProxy(values, ownAddr) && hasOtherLocalProxy(values) {
			found["其他本地系统代理"] = true
		}
	}
	apps := make([]string, 0, len(found))
	for name := range found {
		apps = append(apps, name)
	}
	sort.Strings(apps)
	return apps
}

func hasOtherLocalProxy(v winProxyValues) bool {
	if v.Enable.Present && v.Enable.Value != 0 && v.Server.Present && containsLoopback(v.Server.Value) {
		return true
	}
	return v.AutoConfig.Present && containsLoopback(v.AutoConfig.Value)
}

func containsLoopback(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "127.0.0.1:") || strings.Contains(value, "localhost:") || strings.Contains(value, "[::1]:")
}
