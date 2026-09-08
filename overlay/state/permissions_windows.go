//go:build windows

package state

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

const privateStateSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)"

func secureStateDirectory(path string) error { return setPrivateStateACL(path) }

func secureStateFile(path string) error { return setPrivateStateACL(path) }

func replaceStateFile(source, target string) error {
	sourcePath, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	targetPath, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(sourcePath, targetPath, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func privateStateDirectory(path string, info os.FileInfo) bool {
	return info != nil && info.IsDir() && hasPrivateStateACL(path)
}

func privateStateRegular(path string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && hasPrivateStateACL(path)
}

func statePermissionOK(path string, info os.FileInfo, expected os.FileMode) bool {
	if info == nil {
		return false
	}
	switch expected {
	case 0o700:
		return info.IsDir() && hasPrivateStateACL(path)
	case 0o600:
		return info.Mode().IsRegular() && hasPrivateStateACL(path)
	default:
		return false
	}
}

func setPrivateStateACL(path string) error {
	securityDescriptor, err := windows.SecurityDescriptorFromString(privateStateSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := securityDescriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
}

func hasPrivateStateACL(path string) bool {
	securityDescriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || securityDescriptor == nil {
		return false
	}
	control, _, err := securityDescriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	sddl := securityDescriptor.String()
	if !strings.HasPrefix(sddl, "D:P") {
		return false
	}
	body := strings.TrimPrefix(sddl, "D:P")
	for _, ace := range []string{"(A;;FA;;;SY)", "(A;;FA;;;BA)", "(A;;FA;;;OW)"} {
		if strings.Count(body, ace) != 1 {
			return false
		}
		body = strings.Replace(body, ace, "", 1)
	}
	return body == ""
}
