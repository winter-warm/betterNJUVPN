package core

import (
	"encoding/json"
	"os"
)

// Config 全局配置（config.json，含明文凭据，不入版本库）。
type Config struct {
	Username         string `json:"username"`
	Password         string `json:"password,omitempty"`
	RememberPassword bool   `json:"remember_password"`
	LdapDomain       string `json:"ldap_domain,omitempty"`
	ListenProxy      string `json:"listen_proxy,omitempty"`
	SystemProxy      string `json:"system_proxy,omitempty"`
	ProxyMode        string `json:"proxy_mode,omitempty"`
	DataDir          string `json:"data_dir,omitempty"`
}

// LoadConfig 读取配置文件（不存在则返回默认值），并补全默认字段。
func LoadConfig() (*Config, error) {
	path := ConfigPath()
	cfg := &Config{}
	if data, err := os.ReadFile(path); err == nil {
		if err := SecureFile(path); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return nil, err
		}
		if _, hasChoice := fields["remember_password"]; !hasChoice && cfg.Password != "" {
			cfg.RememberPassword = true
			if err := cfg.Save(); err != nil {
				return nil, err
			}
		}
		if !cfg.RememberPassword && cfg.Password != "" {
			cfg.Password = ""
			if err := cfg.Save(); err != nil {
				return nil, err
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	cfg.fillDefaults()
	return cfg, nil
}

// Save 写回配置。
func (c *Config) Save() error {
	c.fillDefaults()
	stored := *c
	if !stored.RememberPassword {
		stored.Password = ""
	}
	data, err := json.MarshalIndent(&stored, "", "  ")
	if err != nil {
		return err
	}
	path := ConfigPath()
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return SecureFile(path)
}

func (c *Config) fillDefaults() {
	if c.ListenProxy == "" {
		c.ListenProxy = "127.0.0.1:7899"
	}
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	if c.LdapDomain == "" {
		c.LdapDomain = "openldap13924"
	}
	if c.ProxyMode == "" {
		c.ProxyMode = "rule"
	}
	if c.SystemProxy == "" {
		c.SystemProxy = "on"
	}
}

func ConfigPath() string {
	if p := os.Getenv("NJUCONNECT_CONFIG"); p != "" {
		return p
	}
	return "config.json"
}
