//go:build linux || darwin

package main

/*
#cgo linux LDFLAGS: -ldl
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

typedef struct {
	uint32_t status;
	uint64_t size;
	double entropy;
	uint64_t matches;
	char signature[128];
} BhResult;

typedef int (*bh_scan_fn)(const char *, BhResult *);
static bh_scan_fn bh_scanner = NULL;

static int bh_load(const char *library, char *error, size_t error_len) {
	void *handle = dlopen(library, RTLD_NOW | RTLD_LOCAL);
	if (!handle) {
		snprintf(error, error_len, "load scanner library %s: %s", library, dlerror());
		return -1;
	}
	dlerror();
	bh_scan_fn scan = (bh_scan_fn)dlsym(handle, "bytehound_scan");
	const char *symbol_error = dlerror();
	if (symbol_error) {
		snprintf(error, error_len, "find bytehound_scan: %s", symbol_error);
		dlclose(handle);
		return -1;
	}
	bh_scanner = scan;
	return 0;
}

static int bh_scan(const char *path, BhResult *out) {
	if (!bh_scanner) {
		return -1;
	}
	return bh_scanner(path, out);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"
)

var (
	scannerLoadOnce sync.Once
	scannerLoadErr  error
)

func scanNative(path string) (nativeResult, error) {
	scannerLoadOnce.Do(loadNativeScanner)
	if scannerLoadErr != nil {
		return nativeResult{}, scannerLoadErr
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var out C.BhResult
	status := C.bh_scan(cPath, &out)
	if status < 0 {
		return nativeResult{}, errors.New("Rust scanner library is not initialized")
	}
	if out.status != 0 {
		return nativeResult{}, fmt.Errorf("scanner returned status %d for %q", uint32(out.status), path)
	}
	return nativeResult{
		Size:      uint64(out.size),
		Entropy:   float64(out.entropy),
		Matches:   uint64(out.matches),
		Signature: C.GoString(&out.signature[0]),
	}, nil
}

func loadNativeScanner() {
	library, err := findScannerLibrary()
	if err != nil {
		scannerLoadErr = err
		return
	}
	cLibrary := C.CString(library)
	defer C.free(unsafe.Pointer(cLibrary))
	errorBuffer := make([]C.char, 512)
	status := C.bh_load(cLibrary, &errorBuffer[0], C.size_t(len(errorBuffer)))
	if status < 0 {
		scannerLoadErr = fmt.Errorf("%s", C.GoString(&errorBuffer[0]))
	}
}

func findScannerLibrary() (string, error) {
	if configured := os.Getenv("BYTEHOUND_SCANNER_LIB"); configured != "" {
		if _, err := os.Stat(configured); err != nil {
			return "", fmt.Errorf("BYTEHOUND_SCANNER_LIB %q: %w", configured, err)
		}
		return configured, nil
	}
	name := "libbytehound_scanner.so"
	if runtime.GOOS == "darwin" {
		name = "libbytehound_scanner.dylib"
	}
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate executable: %w", err)
	}
	candidates := []string{
		filepath.Join(filepath.Dir(executable), name),
		filepath.Join("scanner", "target", "release", name),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("Rust scanner library %s not found; build it with `make build` or set BYTEHOUND_SCANNER_LIB (searched: %s)", name, strings.Join(candidates, ", "))
}
