//go:build linux

package runtime

import (
	"reflect"
	"testing"
)

func TestSystemdRunArgumentsKeepRuntimeOutsideLoginScope(t *testing.T) {
	got := systemdRunArguments("xconnect-one-xray-test", "/usr/local/bin/xray", []string{"run", "-config", "/state/xray.json"})
	want := []string{
		"--unit", "xconnect-one-xray-test", "--collect", "--quiet",
		"--property=Type=exec", "--property=Restart=no",
		"--property=StandardOutput=null", "--property=StandardError=null",
		"--", "/usr/local/bin/xray", "run", "-config", "/state/xray.json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("systemd-run arguments = %#v", got)
	}
}
