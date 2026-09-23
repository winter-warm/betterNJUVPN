//go:build !windows

package gui

func StopAppProcesses(string) error { return nil }
