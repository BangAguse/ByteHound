//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

type windowsBhResult struct {
	Status    uint32
	Size      uint64
	Entropy   float64
	Matches   uint64
	Signature [128]byte
}

func scanNative(path string) (nativeResult, error) {
	library, err := findScannerLibrary()
	if err != nil {
		return nativeResult{}, err
	}
	dll, err := syscall.LoadDLL(library)
	if err != nil {
		return nativeResult{}, fmt.Errorf("load scanner library %q: %w", library, err)
	}
	defer dll.Release()
	proc, err := dll.FindProc("bytehound_scan")
	if err != nil {
		return nativeResult{}, fmt.Errorf("find bytehound_scan in %q: %w", library, err)
	}
	cPath, err := syscall.BytePtrFromString(path)
	if err != nil {
		return nativeResult{}, fmt.Errorf("encode path %q: %w", path, err)
	}
	var out windowsBhResult
	status, _, callErr := proc.Call(uintptr(unsafe.Pointer(cPath)), uintptr(unsafe.Pointer(&out)))
	runtime.KeepAlive(cPath)
	if status != 0 {
		return nativeResult{}, fmt.Errorf("scanner returned status %d for %q (call error: %v)", out.Status, path, callErr)
	}
	signature := out.Signature[:]
	for i, b := range signature {
		if b == 0 {
			signature = signature[:i]
			break
		}
	}
	return nativeResult{Size: out.Size, Entropy: out.Entropy, Matches: out.Matches, Signature: string(signature)}, nil
}

func findScannerLibrary() (string, error) {
	if configured := os.Getenv("BYTEHOUND_SCANNER_LIB"); configured != "" {
		if _, err := os.Stat(configured); err != nil {
			return "", fmt.Errorf("BYTEHOUND_SCANNER_LIB %q: %w", configured, err)
		}
		return configured, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate executable: %w", err)
	}
	name := "bytehound_scanner.dll"
	candidates := []string{filepath.Join(filepath.Dir(executable), name), filepath.Join("scanner", "target", "release", name)}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("Rust scanner library %s not found; build it with `make build` or set BYTEHOUND_SCANNER_LIB", name)
}
