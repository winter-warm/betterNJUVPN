package core

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"math/big"
)

// 前端 SDK（Tom Wu RSA js 变体）的密码加密：
//   - 明文 = 密码 + "_" + antiReplayRand
//   - 标准 PKCS#1 v1.5 type-2 填充（0x00||0x02||随机非零||0x00||消息）
//   - 分块：每块最多 245 字节（2048bit 模数 - 11），每块独立加密后 hex 顺序拼接
//   - 每块输出定长 hex（模数字节数*2），crypto/rsa 输出天然定长，无需补齐

const sangforChunkSize = 245

// SangforEncrypt 用十六进制模数 pubKeyHex 和十进制指数 exp 加密明文。
func SangforEncrypt(plaintext, pubKeyHex, exp string) (string, error) {
	if exp == "" {
		exp = "65537"
	}
	n, ok := new(big.Int).SetString(pubKeyHex, 16)
	if !ok {
		return "", ErrInvalidPubKey
	}
	eInt, ok := new(big.Int).SetString(exp, 10)
	if !ok {
		return "", ErrInvalidPubKey
	}
	if !eInt.IsInt64() || eInt.Int64() > int64(^uint(0)>>1) {
		return "", ErrInvalidPubKey
	}
	pub := &rsa.PublicKey{N: n, E: int(eInt.Int64())}

	out := ""
	data := []byte(plaintext)
	for off := 0; off < len(data); off += sangforChunkSize {
		end := off + sangforChunkSize
		if end > len(data) {
			end = len(data)
		}
		ct, err := rsa.EncryptPKCS1v15(rand.Reader, pub, data[off:end])
		if err != nil {
			return "", fmt.Errorf("RSA 加密失败: %w", err)
		}
		out += hex.EncodeToString(ct)
	}
	return out, nil
}

// RandomHex 生成 n 字节的随机 hex 字符串（用于 x-sdp-traceid 等）。
func RandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
