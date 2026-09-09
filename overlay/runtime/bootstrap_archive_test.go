package runtime

import (
	"archive/zip"
	"bytes"
	"net/http"
	"testing"
)

type httpHandler func([]byte) []byte

func (handler httpHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	raw := handler(nil)
	writer.Header().Set("Content-Type", "application/zip")
	_, _ = writer.Write(raw)
}

func testXrayArchive(t *testing.T, binary []byte) []byte {
	t.Helper()
	return testNamedXrayArchive(t, "xray", binary)
}

func testNamedXrayArchive(t *testing.T, name string, binary []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	header := &zip.FileHeader{Name: name, Method: zip.Store}
	header.SetMode(0o755)
	file, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(binary); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestExtractXrayBinaryAcceptsWindowsAsset(t *testing.T) {
	raw, err := extractXrayBinary(testNamedXrayArchive(t, "xray.exe", []byte("windows-xray")))
	if err != nil || string(raw) != "windows-xray" {
		t.Fatalf("raw=%q err=%v", raw, err)
	}
}
