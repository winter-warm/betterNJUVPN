//go:build !windows

package gui

func StartProxyWatch(string) error       { return nil }
func RunProxyWatch(uint32, string) error { return nil }
func RecoverProxy(string) error          { return nil }
