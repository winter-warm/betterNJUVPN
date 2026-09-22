//go:build windows

package gui

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

func acquireGUIInstance() (func(), error) {
	name, _ := windows.UTF16PtrFromString(`Local\njuConnectGUI`)
	handle, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if handle != 0 {
			windows.CloseHandle(handle)
		}
		return nil, fmt.Errorf("njuConnect 已在运行，请使用现有窗口")
	}
	if err != nil {
		return nil, err
	}
	return func() { windows.CloseHandle(handle) }, nil
}
