//go:build darwin

package runtime

import (
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

type darwinMappingFileInfo struct {
	name    string
	mode    os.FileMode
	modTime time.Time
	uid     uint32
}

func (f darwinMappingFileInfo) Name() string       { return f.name }
func (f darwinMappingFileInfo) Size() int64        { return 0 }
func (f darwinMappingFileInfo) Mode() os.FileMode  { return f.mode }
func (f darwinMappingFileInfo) ModTime() time.Time { return f.modTime }
func (f darwinMappingFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f darwinMappingFileInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

func newDarwinMappingBackend(raw []byte, mapping, socket os.FileInfo) *osDesktopBackend {
	runtimeDir := "/test-wireguard-runtime"
	paths := map[string]os.FileInfo{
		runtimeDir: mappingFileInfo("runtime", 0755|os.ModeDir, 100, 0),
		filepath.Join(runtimeDir, "xconone0.name"): mapping,
		filepath.Join(runtimeDir, "utun7.sock"):    socket,
	}
	return &osDesktopBackend{
		wireGuardRuntimeDir: runtimeDir,
		lstat: func(path string) (os.FileInfo, error) {
			info, ok := paths[path]
			if !ok {
				return nil, os.ErrNotExist
			}
			return info, nil
		},
		readFile: func(path string) ([]byte, error) {
			if path != filepath.Join(runtimeDir, "xconone0.name") {
				return nil, os.ErrNotExist
			}
			return raw, nil
		},
	}
}

func mappingFileInfo(name string, mode os.FileMode, unixTime int64, uid uint32) os.FileInfo {
	return darwinMappingFileInfo{name: name, mode: mode, modTime: time.Unix(unixTime, 0), uid: uid}
}

func TestDarwinWireGuardMappingMatchesWgQuickContract(t *testing.T) {
	tests := []struct {
		name        string
		mappingMode os.FileMode
		socketMode  os.FileMode
	}{
		{name: "wireguard-go defaults", mappingMode: 0400, socketMode: os.ModeSocket | 0700},
		{name: "owner read-write variants", mappingMode: 0600, socketMode: os.ModeSocket | 0600},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapping := mappingFileInfo("xconone0.name", test.mappingMode, 100, 0)
			socket := mappingFileInfo("utun7.sock", test.socketMode, 101, 0)
			backend := newDarwinMappingBackend([]byte("utun7\n"), mapping, socket)

			got, err := backend.WireGuardInterfaceName("xconone0")
			if err != nil || got != "utun7" {
				t.Fatalf("mapping=%q err=%v", got, err)
			}

			translated, err := backend.translateWireGuardShowArgs("/opt/homebrew/bin/wg", []string{"show", "xconone0", "latest-handshakes"})
			if err != nil || !reflect.DeepEqual(translated, []string{"show", "utun7", "latest-handshakes"}) {
				t.Fatalf("translated=%v err=%v", translated, err)
			}

			configArgs := []string{"up", "/private/tmp/xconnect/runtime/xconone0.conf"}
			unchanged, err := backend.translateWireGuardShowArgs("/opt/homebrew/bin/wg-quick", configArgs)
			if err != nil || !reflect.DeepEqual(unchanged, configArgs) {
				t.Fatalf("wg-quick args=%v err=%v", unchanged, err)
			}
		})
	}
}

func TestDarwinWireGuardMappingRejectsUnsafeOrStaleState(t *testing.T) {
	cases := []struct {
		name    string
		raw     []byte
		mapping os.FileInfo
		socket  os.FileInfo
	}{
		{name: "invalid real name", raw: []byte("utun"), mapping: mappingFileInfo("xconone0.name", 0600, 100, 0), socket: mappingFileInfo("utun7.sock", os.ModeSocket|0600, 100, 0)},
		{name: "mapping symlink", raw: []byte("utun7"), mapping: mappingFileInfo("xconone0.name", os.ModeSymlink|0777, 100, 0), socket: mappingFileInfo("utun7.sock", os.ModeSocket|0600, 100, 0)},
		{name: "mapping wide permissions", raw: []byte("utun7"), mapping: mappingFileInfo("xconone0.name", 0644, 100, 0), socket: mappingFileInfo("utun7.sock", os.ModeSocket|0600, 100, 0)},
		{name: "mapping not root", raw: []byte("utun7"), mapping: mappingFileInfo("xconone0.name", 0600, 100, 501), socket: mappingFileInfo("utun7.sock", os.ModeSocket|0600, 100, 0)},
		{name: "socket symlink", raw: []byte("utun7"), mapping: mappingFileInfo("xconone0.name", 0600, 100, 0), socket: mappingFileInfo("utun7.sock", os.ModeSymlink|0777, 100, 0)},
		{name: "socket wide permissions", raw: []byte("utun7"), mapping: mappingFileInfo("xconone0.name", 0600, 100, 0), socket: mappingFileInfo("utun7.sock", os.ModeSocket|0660, 100, 0)},
		{name: "socket not root", raw: []byte("utun7"), mapping: mappingFileInfo("xconone0.name", 0600, 100, 0), socket: mappingFileInfo("utun7.sock", os.ModeSocket|0600, 100, 501)},
		{name: "stale mapping", raw: []byte("utun7"), mapping: mappingFileInfo("xconone0.name", 0600, 100, 0), socket: mappingFileInfo("utun7.sock", os.ModeSocket|0600, 102, 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend := newDarwinMappingBackend(tc.raw, tc.mapping, tc.socket)
			if got, err := backend.WireGuardInterfaceName("xconone0"); err == nil || got != "" {
				t.Fatalf("accepted unsafe mapping=%q err=%v", got, err)
			}
		})
	}

	backend := newDarwinMappingBackend([]byte("utun7"), mappingFileInfo("xconone0.name", 0600, 100, 0), mappingFileInfo("utun7.sock", os.ModeSocket|0600, 100, 0))
	if _, err := backend.WireGuardInterfaceName("../xconone0"); err == nil {
		t.Fatal("accepted invalid logical interface name")
	}
}

func TestDarwinWireGuardRuntimeDirectoryRejectsUnsafeState(t *testing.T) {
	cases := []struct {
		name string
		info os.FileInfo
	}{
		{name: "symlink", info: mappingFileInfo("runtime", os.ModeDir|os.ModeSymlink|0777, 100, 0)},
		{name: "not root", info: mappingFileInfo("runtime", os.ModeDir|0755, 100, 501)},
		{name: "wide permissions", info: mappingFileInfo("runtime", os.ModeDir|0777, 100, 0)},
		{name: "not directory", info: mappingFileInfo("runtime", 0600, 100, 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateDarwinRuntimeDirectory(func(string) (os.FileInfo, error) { return tc.info, nil }, "/test-wireguard-runtime"); err == nil {
				t.Fatal("accepted unsafe runtime directory")
			}
		})
	}
}

type darwinStatusBackend struct {
	*fakeDesktopBackend
}

func (b *darwinStatusBackend) WireGuardInterfaceName(string) (string, error) {
	return "utun7", nil
}

func TestDarwinDesktopStatusReportsRealInterfaceAndKeepsAdapterID(t *testing.T) {
	backend := &darwinStatusBackend{fakeDesktopBackend: newFakeDesktopBackend()}
	tunnelRuntime := newDesktop(t.TempDir(), backend)
	request := desktopApplyRequest("revision-darwin")
	if _, err := tunnelRuntime.Apply(t.Context(), request); err != nil {
		t.Fatalf("apply: %v", err)
	}
	status, err := tunnelRuntime.Status(t.Context())
	if err != nil || !status.Applied || status.Interface != "utun7" || status.AdapterID != "xray-core" {
		t.Fatalf("status=%#v err=%v", status, err)
	}
}
