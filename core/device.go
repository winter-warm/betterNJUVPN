package core

import (
	"encoding/base64"
	"encoding/json"
	"os"
)

// ClientlessEnvBlob 生成免客户端模式下的 x-sdp-env 值：
// base64(JSON{"deviceId": ...})，deviceId 持久化到设备文件以保持稳定
// （对应官方 SPA 无 Agent 时 localStorage 存储的 deviceId）。
func (s *Session) ClientlessEnvBlob() string {
	id := loadDeviceID()
	if id == "" {
		id = RandomHex(32)
		_ = saveDeviceID(id)
	}
	blob, _ := json.Marshal(map[string]string{"deviceId": id})
	return base64.StdEncoding.EncodeToString(blob)
}

func deviceFile() string {
	if p := os.Getenv("NJUCONNECT_CONFIG"); p != "" {
		return "device.json"
	}
	return "data/device.json"
}

func loadDeviceID() string {
	data, err := os.ReadFile(deviceFile())
	if err != nil {
		return ""
	}
	var d struct {
		DeviceID string `json:"deviceId"`
	}
	if json.Unmarshal(data, &d) != nil {
		return ""
	}
	return d.DeviceID
}

func saveDeviceID(id string) error {
	data, err := json.MarshalIndent(map[string]string{"deviceId": id}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(deviceFile(), data, 0600)
}
