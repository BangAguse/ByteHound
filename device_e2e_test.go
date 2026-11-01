//go:build linux || darwin

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeviceScanWithADBStub(t *testing.T) {
	if _, err := findScannerLibrary(); err != nil {
		t.Skip("build the Rust scanner with `make build` to run the ADB integration test")
	}
	dir := t.TempDir()
	fixture := filepath.Join(dir, "remote-file")
	if err := os.WriteFile(fixture, []byte("EICAR-STANDARD-ANTIVIRUS-TEST-FILE"), 0600); err != nil {
		t.Fatal(err)
	}
	adbStub := filepath.Join(dir, "adb")
	script := `#!/bin/sh
if [ "$1" = "devices" ]; then
  printf 'List of devices attached\nphone-test\tdevice\n'
  exit 0
fi
if [ "$1" = "-s" ]; then
  shift 2
fi
case "$1" in
  exec-out)
    printf '/sdcard/Download/marker.py\000'
    ;;
  pull)
    cp "$BYTEHOUND_TEST_FIXTURE" "$3"
    ;;
  *)
    echo "unexpected adb command: $*" >&2
    exit 2
    ;;
esac
`
	if err := os.WriteFile(adbStub, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("BYTEHOUND_TEST_FIXTURE", fixture)

	var stdout, stderr bytes.Buffer
	summary, err := runDeviceScan(options{device: true, verbose: true}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runDeviceScan() failed: %v; stderr: %s", err, stderr.String())
	}
	if summary.FindingCount != 1 || len(summary.Results) != 1 {
		t.Fatalf("unexpected device scan summary: %#v", summary)
	}
	if summary.Results[0].Path != "/sdcard/Download/marker.py" || !summary.Results[0].Suspicious {
		t.Fatalf("unexpected device scan result: %#v", summary.Results[0])
	}
	if !strings.Contains(stdout.String(), "Android device phone-test:/sdcard") ||
		!strings.Contains(stdout.String(), "Scanned /sdcard/Download/marker.py") {
		t.Fatalf("unexpected device scan output: %s", stdout.String())
	}
}
