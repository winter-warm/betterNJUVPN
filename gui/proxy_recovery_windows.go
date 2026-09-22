//go:build windows

package gui

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// StartProxyWatch starts a small copy of this executable. It restores the
// saved user proxy settings if the GUI process is killed without StopProxy.
func StartProxyWatch(dataDir string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "recover-watch", strconv.Itoa(os.Getpid()), dataDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func RunProxyWatch(parentPID uint32, dataDir string) error {
	m := newSystemProxyManager(dataDir)
	parent, err := windows.OpenProcess(windows.SYNCHRONIZE, false, parentPID)
	if err != nil {
		return m.Restore()
	}
	defer windows.CloseHandle(parent)
	for {
		if _, err := os.Stat(m.stateFile); os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
		status, err := windows.WaitForSingleObject(parent, uint32((250*time.Millisecond)/time.Millisecond))
		if err != nil {
			return fmt.Errorf("等待主程序退出失败: %w", err)
		}
		if status == windows.WAIT_OBJECT_0 {
			return m.Restore()
		}
		if status != uint32(windows.WAIT_TIMEOUT) {
			return fmt.Errorf("等待主程序返回异常状态 %d", status)
		}
	}
}

func RecoverProxy(dataDir string) error { return newSystemProxyManager(dataDir).Restore() }
