//go:build !windows

package gui

func acquireGUIInstance() (func(), error) { return func() {}, nil }
