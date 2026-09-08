//go:build !windows

package state

import "os"

func secureStateDirectory(path string) error { return os.Chmod(path, 0o700) }

func secureStateFile(path string) error { return os.Chmod(path, 0o600) }

func replaceStateFile(source, target string) error { return os.Rename(source, target) }

func privateStateDirectory(_ string, info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode().Perm() == 0o700
}

func privateStateRegular(_ string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600
}

func statePermissionOK(_ string, info os.FileInfo, expected os.FileMode) bool {
	return info != nil && info.Mode().Perm() == expected
}
