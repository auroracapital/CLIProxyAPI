//go:build windows

package auth

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func lockReconcilePath(path string) (func(), error) {
	parentInfo, errParent := os.Lstat(filepath.Dir(path))
	if errParent != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("auth filestore: reconcile lock directory is unsafe")
	}
	file, errOpen := os.OpenFile(path+".reconcile.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if errOpen != nil {
		return nil, fmt.Errorf("auth filestore: open reconcile lock: %w", errOpen)
	}
	info, errStat := file.Stat()
	if errStat != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("auth filestore: reconcile lock is unsafe")
	}
	overlapped := new(windows.Overlapped)
	if errLock := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, overlapped); errLock != nil {
		_ = file.Close()
		return nil, fmt.Errorf("auth filestore: acquire reconcile lock: %w", errLock)
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, overlapped)
		_ = file.Close()
	}, nil
}
