//go:build windows

package gui

import "syscall"

// Windows must know the process DPI mode before WebView2 creates its first window.
func enableHighDPI() {
	user32 := syscall.NewLazyDLL("user32.dll")
	setContext := user32.NewProc("SetProcessDpiAwarenessContext")
	// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 is the signed handle -4.
	if setContext.Find() == nil {
		if ok, _, _ := setContext.Call(^uintptr(3)); ok != 0 {
			return
		}
	}
	// Fallback for older Windows releases.
	shcore := syscall.NewLazyDLL("shcore.dll").NewProc("SetProcessDpiAwareness")
	if shcore.Find() == nil {
		if result, _, _ := shcore.Call(2); result == 0 {
			return
		}
	}
	_, _, _ = user32.NewProc("SetProcessDPIAware").Call()
}
