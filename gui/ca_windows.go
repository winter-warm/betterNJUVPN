//go:build windows

package gui

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
	"njuconnect/proxy"
)

func localCATrusted(dataDir string) bool {
	data, err := os.ReadFile(filepath.Join(dataDir, "ca.pem"))
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	_, err = cert.Verify(x509.VerifyOptions{KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

// TrustLocalCA is invoked only by an explicit UI action or the installer's
// selected certificate task. It trusts this installation's generated CA for
// the current Windows user, never the machine-wide store.
func TrustLocalCA(dataDir string) error {
	if _, err := proxy.LoadOrGenerateCA(dataDir); err != nil {
		return err
	}
	certPath, err := filepath.Abs(filepath.Join(dataDir, "ca.pem"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "certutil.exe", "-f", "-user", "-addstore", "Root", certPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("信任本地证书失败: %w: %s", err, output)
	}
	if !localCATrusted(dataDir) {
		return fmt.Errorf("证书导入后仍未被当前用户信任")
	}
	return nil
}

// UntrustLocalCA removes only the certificate generated in this data directory.
func UntrustLocalCA(dataDir string) error {
	data, err := os.ReadFile(filepath.Join(dataDir, "ca.pem"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("本地 CA 文件无效，未修改证书存储")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if !localCATrusted(dataDir) {
		return nil
	}
	thumbprint := sha1.Sum(cert.Raw) // Windows certificate store identifies certs by SHA-1 thumbprint.
	key := `Software\Microsoft\SystemCertificates\Root\Certificates\` + strings.ToUpper(hex.EncodeToString(thumbprint[:]))
	if err := registry.DeleteKey(registry.CURRENT_USER, key); err != nil && err != registry.ErrNotExist {
		return fmt.Errorf("移除本地证书失败: %w", err)
	}
	if localCATrusted(dataDir) {
		return fmt.Errorf("证书删除后仍被当前用户信任")
	}
	return nil
}
