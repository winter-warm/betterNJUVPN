//go:build windows

package core

import (
	"fmt"
	"os/exec"
	"os/user"
	"syscall"

	"golang.org/x/sys/windows"
)

// SecureFile removes inherited broad ACLs from a secret file. Windows does not
// apply the Unix 0600 mode passed to os.WriteFile to NTFS ACLs.
func SecureFile(path string) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	cmd := exec.Command("icacls.exe", path, "/inheritance:r", "/grant:r",
		"*"+u.Uid+":F", "*S-1-5-18:F", "*S-1-5-32-544:F")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("限制文件权限失败: %w: %s", err, out)
	}
	return nil
}
