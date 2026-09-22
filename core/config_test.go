package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRememberPasswordControlsDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("NJUCONNECT_CONFIG", path)
	c := &Config{Username: "student", Password: "secret", RememberPassword: false}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret") {
		t.Fatal("unchecked password was saved")
	}
	c.RememberPassword = true
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "secret") {
		t.Fatal("checked password was not saved")
	}
}

func TestExistingSavedPasswordKeepsCheckedChoice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("NJUCONNECT_CONFIG", path)
	if err := os.WriteFile(path, []byte(`{"username":"student","password":"secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !c.RememberPassword || c.Password != "secret" {
		t.Fatal("existing saved password was not retained")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"remember_password": true`) {
		t.Fatal("choice was not recorded")
	}
}
