package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

type adbDevice struct {
	serial string
	state  string
}

func runDeviceScan(opts options, stdout, stderr io.Writer) (scanSummary, error) {
	adb, err := exec.LookPath("adb")
	if err != nil {
		return scanSummary{}, errors.New("ADB was not found; install Android Platform Tools and make sure `adb` is on PATH")
	}
	devices, err := listADBDevices(adb)
	if err != nil {
		return scanSummary{}, err
	}
	device, err := chooseADBDevice(devices, opts.deviceSerial)
	if err != nil {
		return scanSummary{}, err
	}

	root := fmt.Sprintf("Android device %s:/sdcard", device.serial)
	printScanStart(stdout, root, opts.fast)
	started := time.Now()
	summary := scanSummary{Root: root, StartedAt: started}

	tempDir, err := os.MkdirTemp("", "bytehound-device-*")
	if err != nil {
		return summary, fmt.Errorf("create temporary scan directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	listPath, listErr := listSharedStorage(adb, device.serial, tempDir)
	if listPath == "" {
		return summary, listErr
	}
	defer os.Remove(listPath)
	if listErr != nil {
		summary.ErrorCount++
		fmt.Fprintf(stderr, "Warning: shared-storage listing was incomplete: %v\n", listErr)
	}

	reader, err := os.Open(listPath)
	if err != nil {
		return summary, fmt.Errorf("read Android file list: %w", err)
	}
	defer reader.Close()
	total, err := countNULPaths(reader)
	if err != nil {
		return summary, fmt.Errorf("count Android shared-storage files: %w", err)
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return summary, fmt.Errorf("rewind Android file list: %w", err)
	}

	color := supportsColor(stdout)
	processed := 0
	buffered := bufio.NewReader(reader)
	for {
		remotePath, readErr := readNULPath(buffered)
		if len(remotePath) > 0 {
			processed++
			if opts.fast && !shouldScanFast(remotePath, 0) {
				summary.Skipped++
			} else {
				result := scanDeviceFile(adb, device.serial, remotePath, tempDir)
				if result.Error != "" {
					summary.ErrorCount++
				}
				if result.Suspicious {
					summary.FindingCount++
				}
				summary.Results = append(summary.Results, result)
				if opts.verbose {
					if result.Error != "" {
						fmt.Fprintf(stdout, "%s %s: %s\n", style("Error", colorRed, color), result.Path, result.Error)
					} else {
						fmt.Fprintf(stdout, "%s %s\n", style("Scanned", colorMuted, color), result.Path)
					}
				}
			}
			if !opts.verbose {
				fmt.Fprintf(stdout, "\r%s", renderProgress(processed, total, summary.FindingCount, color))
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return summary, fmt.Errorf("read Android file list: %w", readErr)
			}
			break
		}
	}
	if !opts.verbose && total > 0 {
		fmt.Fprintln(stdout)
	}
	sort.Slice(summary.Results, func(i, j int) bool {
		return summary.Results[i].Path < summary.Results[j].Path
	})
	summary.Duration = time.Since(started)
	return summary, nil
}

func listADBDevices(adb string) ([]adbDevice, error) {
	output, err := exec.Command(adb, "devices").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("run ADB device discovery: %w: %s", err, strings.TrimSpace(string(output)))
	}
	var devices []adbDevice
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] != "List" {
			devices = append(devices, adbDevice{serial: fields[0], state: fields[1]})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read ADB device list: %w", err)
	}
	return devices, nil
}

func chooseADBDevice(devices []adbDevice, requestedSerial string) (adbDevice, error) {
	var ready []adbDevice
	var unauthorized bool
	for _, device := range devices {
		if device.state == "device" {
			ready = append(ready, device)
		}
		if device.state == "unauthorized" {
			unauthorized = true
		}
	}
	if requestedSerial != "" {
		for _, device := range devices {
			if device.serial == requestedSerial {
				if device.state != "device" {
					return adbDevice{}, fmt.Errorf("Android device %q is %s; unlock the phone and authorize USB debugging", requestedSerial, device.state)
				}
				return device, nil
			}
		}
		return adbDevice{}, fmt.Errorf("ADB device %q was not found; check `adb devices`", requestedSerial)
	}
	if len(ready) == 1 {
		return ready[0], nil
	}
	if len(ready) > 1 {
		return adbDevice{}, errors.New("multiple Android devices are connected; choose one with --device-serial <serial>")
	}
	if unauthorized {
		return adbDevice{}, errors.New("Android device is unauthorized; unlock it and accept the USB debugging prompt, then retry")
	}
	return adbDevice{}, errors.New("no authorized Android device found; connect it with a data-capable USB cable and enable USB debugging")
}

func listSharedStorage(adb, serial, tempDir string) (string, error) {
	listFile, err := os.CreateTemp(tempDir, "device-files-*.nul")
	if err != nil {
		return "", fmt.Errorf("create temporary file list: %w", err)
	}
	listPath := listFile.Name()
	cmd := exec.Command(adb, "-s", serial, "exec-out", "find", "/sdcard", "-type", "f", "-print0")
	cmd.Stdout = listFile
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	closeErr := listFile.Close()
	if closeErr != nil {
		os.Remove(listPath)
		return "", fmt.Errorf("finish writing Android file list: %w", closeErr)
	}
	if runErr != nil {
		info, statErr := os.Stat(listPath)
		if statErr != nil || info.Size() == 0 {
			os.Remove(listPath)
			return "", fmt.Errorf("list Android shared storage: %w: %s", runErr, strings.TrimSpace(stderr.String()))
		}
		return listPath, fmt.Errorf("%w: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	return listPath, nil
}

func readNULPath(reader *bufio.Reader) (string, error) {
	path, err := reader.ReadBytes(0)
	if errors.Is(err, io.EOF) && len(path) > 0 {
		return string(path), nil
	}
	if err != nil {
		return "", err
	}
	return string(path[:len(path)-1]), nil
}

func countNULPaths(reader io.Reader) (int, error) {
	buffer := make([]byte, 64*1024)
	count, hasTrailingPath := 0, false
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			for _, b := range buffer[:n] {
				if b == 0 {
					count++
					hasTrailingPath = false
				} else {
					hasTrailingPath = true
				}
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return 0, err
			}
			break
		}
	}
	if hasTrailingPath {
		count++
	}
	return count, nil
}

func scanDeviceFile(adb, serial, remotePath, tempDir string) fileResult {
	result := fileResult{Path: remotePath}
	localFile, err := os.CreateTemp(tempDir, "file-*")
	if err != nil {
		result.Error = fmt.Sprintf("create temporary file: %v", err)
		return result
	}
	localPath := localFile.Name()
	if err := localFile.Close(); err != nil {
		os.Remove(localPath)
		result.Error = fmt.Sprintf("close temporary file: %v", err)
		return result
	}
	defer os.Remove(localPath)

	output, err := exec.Command(adb, "-s", serial, "pull", remotePath, localPath).CombinedOutput()
	if err != nil {
		result.Error = fmt.Sprintf("ADB pull failed: %v: %s", err, strings.TrimSpace(string(output)))
		return result
	}
	info, err := os.Stat(localPath)
	if err != nil {
		result.Error = fmt.Sprintf("inspect temporary file: %v", err)
		return result
	}
	native, err := scanNative(localPath)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Size = native.Size
	result.Entropy = native.Entropy
	result.Matches = native.Matches
	result.Signature = native.Signature
	if native.Matches > 0 {
		result.Suspicious = true
		result.Reasons = append(result.Reasons, fmt.Sprintf("matched heuristic signature %q (%d match(es))", native.Signature, native.Matches))
	}
	if info.Size() >= 4096 && native.Entropy >= entropyThreshold {
		result.Suspicious = true
		result.Reasons = append(result.Reasons, fmt.Sprintf("high entropy (%.3f bits/byte)", native.Entropy))
	}
	return result
}
