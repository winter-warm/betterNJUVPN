package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"njuconnect/core"
)

// CA 管理本地根证书，按需签发叶子证书（HTTPS MITM 用）。

type CertAuthority struct {
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
	mu     sync.Mutex
	cache  map[string]*tls.Certificate
}

// LoadOrGenerateCA 从 dir 加载 ca.pem/ca.key，不存在则生成。
func LoadOrGenerateCA(dir string) (*CertAuthority, error) {
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			if err := core.SecureFile(keyPath); err != nil {
				return nil, err
			}
			certPEM, err := os.ReadFile(certPath)
			if err != nil {
				return nil, err
			}
			keyPEM, err := os.ReadFile(keyPath)
			if err != nil {
				return nil, err
			}
			cert, key, err := parseCertKey(certPEM, keyPEM)
			if err != nil {
				return nil, fmt.Errorf("解析 CA 失败: %w", err)
			}
			return newCA(cert, key), nil
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "njuConnect Local CA", Organization: []string{"njuconnect"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, err
	}
	if err := core.SecureFile(keyPath); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	fmt.Printf("[CA] 已生成本地根证书: %s\n      请将其导入系统/浏览器的受信任根证书（详情见 README）\n", certPath)
	return newCA(cert, key), nil
}

func newCA(cert *x509.Certificate, key *rsa.PrivateKey) *CertAuthority {
	return &CertAuthority{caCert: cert, caKey: key, cache: map[string]*tls.Certificate{}}
}

func parseCertKey(certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	var block *pem.Block
	block, _ = pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("证书 PEM 无效")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("私钥 PEM 无效")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// LeafForHost 为 host 签发（或取缓存）叶子证书。
func (ca *CertAuthority) LeafForHost(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.cache[host]; ok {
		return c, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, 30),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := parseIP(host); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, &key.PublicKey, ca.caKey)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{
		Certificate: [][]byte{der, ca.caCert.Raw},
		PrivateKey:  key,
	}
	ca.cache[host] = leaf
	return leaf, nil
}

func parseIP(s string) net.IP {
	return net.ParseIP(s)
}
