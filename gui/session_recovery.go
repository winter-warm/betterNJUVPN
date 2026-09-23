package gui

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"njuconnect/core"
)

// Preserve malformed data for recovery. Permission and I/O errors must not
// silently discard a valid session; automatic startup never starts a new login.
func loadLoginSession(sess *core.Session, path string, auto bool) error {
	err := sess.Load(path)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	var syntax *json.SyntaxError
	var typeError *json.UnmarshalTypeError
	if !errors.As(err, &syntax) && !errors.As(err, &typeError) {
		return err
	}
	if auto {
		return fmt.Errorf("会话文件损坏，请手动登录以重新建立会话: %w", err)
	}
	backup := path + ".corrupt-" + time.Now().Format("20060102-150405.000000000")
	if err := os.Rename(path, backup); err != nil {
		return fmt.Errorf("备份损坏会话失败: %w", err)
	}
	return nil
}
