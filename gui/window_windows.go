//go:build windows

package gui

import (
	"syscall"
	"unsafe"
)

// Fill the current monitor's work area without placing part of the window
// beyond smaller displays or behind the taskbar.
func maximizeWindow(hwnd unsafe.Pointer) {
	const swMaximize = 3
	_, _, _ = syscall.NewLazyDLL("user32.dll").NewProc("ShowWindow").Call(uintptr(hwnd), swMaximize)
}
