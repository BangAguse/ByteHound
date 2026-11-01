package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	appName        = "ByteHound"
	appVersion     = "0.1"
	author         = "Muh. Agus Tri Ananda"
	githubUsername = "BangAguse"
)

type options struct {
	root         string
	output       string
	device       bool
	deviceSerial string
	verbose      bool
	fast         bool
	help         bool
}

func main() {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(2)
	}
	if opts.help {
		printHelp(os.Stdout)
		return
	}

	printBanner(os.Stdout)
	var summary scanSummary
	if opts.device {
		summary, err = runDeviceScan(opts, os.Stdout, os.Stderr)
	} else {
		absoluteRoot, absErr := filepath.Abs(opts.root)
		if absErr != nil {
			fmt.Fprintln(os.Stderr, "Error resolving scan path:", absErr)
			os.Exit(1)
		}
		printScanStart(os.Stdout, absoluteRoot, opts.fast)
		summary, err = runScan(opts, os.Stdout, os.Stderr)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Scan failed:", err)
		os.Exit(1)
	}
	printScanSummary(os.Stdout, summary)
	if opts.output != "" {
		if err := writeReport(opts.output, summary); err != nil {
			fmt.Fprintln(os.Stderr, "Report error:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stdout, "\n%s %s\n", style("Report saved", colorTeal, supportsColor(os.Stdout)), opts.output)
	}
}

func parseOptions(args []string) (options, error) {
	var opts options
	flags := flag.NewFlagSet(appName, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.BoolVar(&opts.help, "h", false, "Show this help")
	flags.BoolVar(&opts.help, "help", false, "Show this help")
	flags.BoolVar(&opts.verbose, "v", false, "Print every file as it is scanned")
	flags.BoolVar(&opts.verbose, "verbose", false, "Print every file as it is scanned")
	flags.StringVar(&opts.root, "path", ".", "Directory to scan")
	flags.StringVar(&opts.output, "o", "", "Write report (.txt, .json, .pdf, or .csv)")
	flags.StringVar(&opts.output, "output", "", "Write report (.txt, .json, .pdf, or .csv)")
	flags.BoolVar(&opts.device, "device", false, "Scan accessible Android shared storage over USB using ADB")
	flags.StringVar(&opts.deviceSerial, "device-serial", "", "Select an attached Android device by ADB serial")
	flags.BoolVar(&opts.fast, "fast", false, "Scan critical extensions only and skip large media files")
	if err := flags.Parse(args); err != nil {
		return opts, err
	}
	if flags.NArg() != 0 {
		return opts, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	if opts.deviceSerial != "" && !opts.device {
		return opts, errors.New("--device-serial requires --device")
	}
	if opts.device && opts.root != "." {
		return opts, errors.New("--path cannot be combined with --device")
	}
	if opts.root == "" {
		opts.root = "."
	}
	if !opts.device {
		info, err := os.Stat(opts.root)
		if err != nil {
			return opts, fmt.Errorf("cannot access scan path %q: %w", opts.root, err)
		}
		if !info.IsDir() {
			return opts, fmt.Errorf("scan path %q is not a directory", opts.root)
		}
	}
	if opts.output != "" {
		switch strings.ToLower(filepath.Ext(opts.output)) {
		case ".txt", ".json", ".pdf", ".csv":
		default:
			return opts, errors.New("unsupported report extension; use .txt, .json, .pdf, or .csv")
		}
	}
	return opts, nil
}

func printHelp(w io.Writer) {
	fmt.Fprintf(w, `%s %s
Author: %s
GitHub: %s

Usage:
  bytehound [options]

Options:
  -h, --help           Show this complete usage guide
  -v, --verbose        Print each file being scanned in real time
      --path <dir>     Scan this directory (default: current directory)
  -o, --output <file>  Save a report; extension selects .txt, .json, .pdf, or .csv
      --fast           Scan critical source/executable extensions only and skip
                       media files larger than 64 MiB
      --device         Scan accessible Android shared storage over USB (requires ADB)
      --device-serial  Choose a connected device when multiple phones are attached

Examples:
  bytehound
  bytehound --path ./evidence --verbose
  bytehound --path ./evidence --fast --output report.json
  bytehound --device --verbose
  bytehound --device --device-serial <serial> --output phone.json

Notes:
  ByteHound reports heuristic indicators, not a malware verdict. High entropy is
  common in archives, compressed files, and encrypted data. The bundled
  signatures are examples, not a comprehensive or regularly updated threat feed.
  Android device mode scans shared storage (/sdcard) only. Android does not expose
  private app data or protected system files without root; USB debugging must be
  enabled and this computer authorized on the phone.
  Scan only directories you are authorized to examine.
`, appName, appVersion, author, githubUsername)
}

func defaultWorkers() int {
	n := runtime.NumCPU()
	if n > 32 {
		return 32
	}
	return n
}
