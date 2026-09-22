//go:build !windows

package core

func SecureFile(path string) error { return nil }
