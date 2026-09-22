//go:build !windows

package gui

import "fmt"

type tunManager struct{}

func newTunManager() *tunManager { return &tunManager{} }
func tunIsElevated() bool        { return false }
func (m *tunManager) Start(_, _ string) error {
	return fmt.Errorf("虚拟网卡仅支持 Windows")
}
func (m *tunManager) Stop() error   { return nil }
func (m *tunManager) Running() bool { return false }
