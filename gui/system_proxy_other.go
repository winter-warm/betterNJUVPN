//go:build !windows

package gui

import "fmt"

type systemProxyManager struct{}

func newSystemProxyManager(string) *systemProxyManager { return &systemProxyManager{} }
func (m *systemProxyManager) Enable(addr, mode string) error {
	return fmt.Errorf("系统代理仅支持 Windows")
}
func (m *systemProxyManager) Restore() error                  { return nil }
func (m *systemProxyManager) ClearStaleOwnProxy(string) error { return nil }
func ClearStaleOwnProxy(string, string) error                 { return nil }
