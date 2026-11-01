package main

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestChooseADBDevice(t *testing.T) {
	devices := []adbDevice{
		{serial: "phone-1", state: "device"},
		{serial: "phone-2", state: "offline"},
	}
	t.Run("selects only authorized device", func(t *testing.T) {
		got, err := chooseADBDevice(devices, "")
		if err != nil || got.serial != "phone-1" {
			t.Fatalf("chooseADBDevice() = %#v, %v", got, err)
		}
	})
	t.Run("requires serial for multiple phones", func(t *testing.T) {
		_, err := chooseADBDevice(append(devices, adbDevice{serial: "phone-3", state: "device"}), "")
		if err == nil || !strings.Contains(err.Error(), "--device-serial") {
			t.Fatalf("expected serial-selection guidance, got %v", err)
		}
	})
	t.Run("explains authorization requirement", func(t *testing.T) {
		_, err := chooseADBDevice([]adbDevice{{serial: "phone-1", state: "unauthorized"}}, "")
		if err == nil || !strings.Contains(err.Error(), "USB debugging") {
			t.Fatalf("expected USB-debugging guidance, got %v", err)
		}
	})
	t.Run("rejects unavailable requested serial", func(t *testing.T) {
		_, err := chooseADBDevice(devices, "missing")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("expected missing-device error, got %v", err)
		}
	})
}

func TestReadNULPath(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("/sdcard/dir with spaces/file\nname.txt\x00/sdcard/final.txt"))
	first, err := readNULPath(reader)
	if err != nil || first != "/sdcard/dir with spaces/file\nname.txt" {
		t.Fatalf("first path = %q, %v", first, err)
	}
	last, err := readNULPath(reader)
	if err != nil || last != "/sdcard/final.txt" {
		t.Fatalf("last path = %q, %v", last, err)
	}
	if _, err := readNULPath(reader); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestCountNULPaths(t *testing.T) {
	for input, want := range map[string]int{
		"":                            0,
		"/sdcard/a\x00/sdcard/b\x00":  2,
		"/sdcard/a\x00/sdcard/final":  2,
		"/sdcard/single-without-null": 1,
	} {
		got, err := countNULPaths(strings.NewReader(input))
		if err != nil || got != want {
			t.Errorf("countNULPaths(%q) = %d, %v; want %d", input, got, err, want)
		}
	}
}

func TestDeviceOptions(t *testing.T) {
	opts, err := parseOptions([]string{"--device", "--device-serial", "phone-1", "--output", "report.json"})
	if err != nil || !opts.device || opts.deviceSerial != "phone-1" {
		t.Fatalf("device options rejected: %#v, %v", opts, err)
	}
	if _, err := parseOptions([]string{"--device-serial", "phone-1"}); err == nil {
		t.Fatal("device serial without --device should fail")
	}
	if _, err := parseOptions([]string{"--device", "--path", "/tmp"}); err == nil {
		t.Fatal("--device and --path should not be combined")
	}
}
