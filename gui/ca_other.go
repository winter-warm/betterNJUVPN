//go:build !windows

package gui

import "fmt"

func localCATrusted(_ string) bool  { return false }
func TrustLocalCA(_ string) error   { return fmt.Errorf("本地证书信任仅支持 Windows") }
func UntrustLocalCA(_ string) error { return nil }
