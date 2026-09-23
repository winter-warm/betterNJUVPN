//go:build windows

package gui

import (
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var queryFullProcessImageName = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryFullProcessImageNameW")

// StopAppProcesses stops only processes executing the installed GUI binary.
// The uninstaller calls this before restoring proxy settings or deleting files.
func StopAppProcesses(appExe string) error {
	want, err := filepath.Abs(appExe)
	if err != nil {
		return err
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return err
	}
	for {
		if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), filepath.Base(want)) {
			if err := stopProcessAtPath(entry.ProcessID, want); err != nil {
				return err
			}
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				return nil
			}
			return err
		}
	}
}

func stopProcessAtPath(pid uint32, want string) error {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if err == windows.ERROR_INVALID_PARAMETER { // Process exited during enumeration.
		return nil
	}
	if err != nil {
		return fmt.Errorf("检查应用进程 %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	r, _, callErr := queryFullProcessImageName.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return fmt.Errorf("读取应用进程 %d 路径: %w", pid, callErr)
	}
	if !strings.EqualFold(filepath.Clean(windows.UTF16ToString(buf[:size])), filepath.Clean(want)) {
		return nil
	}
	if err := windows.TerminateProcess(handle, 0); err != nil {
		return fmt.Errorf("结束应用进程 %d: %w", pid, err)
	}
	status, err := windows.WaitForSingleObject(handle, 5000)
	if err != nil {
		return err
	}
	if status != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("等待应用进程 %d 退出超时", pid)
	}
	return nil
}
