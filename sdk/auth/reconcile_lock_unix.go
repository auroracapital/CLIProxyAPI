//go:build !windows

package auth

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func lockReconcilePath(path string) (func(), error) {
	parentInfo, errParent := os.Lstat(filepath.Dir(path))
	if errParent != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("auth filestore: reconcile lock directory is unsafe")
	}
	lockPath := path + ".reconcile.lock"
	file, errOpen := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if errOpen != nil {
		return nil, fmt.Errorf("auth filestore: open reconcile lock: %w", errOpen)
	}
	if errChmod := file.Chmod(0o600); errChmod != nil {
		_ = file.Close()
		return nil, fmt.Errorf("auth filestore: secure reconcile lock: %w", errChmod)
	}
	info, errStat := file.Stat()
	if errStat != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = file.Close()
		return nil, fmt.Errorf("auth filestore: reconcile lock is unsafe")
	}
	if errFlock := unix.Flock(int(file.Fd()), unix.LOCK_EX); errFlock != nil {
		_ = file.Close()
		return nil, fmt.Errorf("auth filestore: acquire reconcile lock: %w", errFlock)
	}
	return func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	}, nil
}
