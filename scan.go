package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	entropyThreshold = 7.2
	mediaSkipSize    = 64 << 20
)

type fileResult struct {
	Path       string   `json:"path"`
	Size       uint64   `json:"size_bytes"`
	Entropy    float64  `json:"entropy_bits_per_byte"`
	Matches    uint64   `json:"signature_matches"`
	Signature  string   `json:"signature,omitempty"`
	Suspicious bool     `json:"suspicious"`
	Reasons    []string `json:"reasons,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type scanSummary struct {
	Root         string        `json:"root"`
	StartedAt    time.Time     `json:"started_at"`
	Duration     time.Duration `json:"duration"`
	Results      []fileResult  `json:"results"`
	Skipped      int           `json:"skipped"`
	FindingCount int           `json:"finding_count"`
	ErrorCount   int           `json:"error_count"`
}

func runScan(opts options, stdout, stderr io.Writer) (scanSummary, error) {
	root, err := filepath.Abs(opts.root)
	if err != nil {
		return scanSummary{}, fmt.Errorf("resolve scan path: %w", err)
	}
	started := time.Now()
	summary := scanSummary{Root: root, StartedAt: started}
	var paths []string
	walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			fmt.Fprintf(stderr, "Cannot access %s: %v\n", path, walkErr)
			summary.Results = append(summary.Results, fileResult{Path: path, Error: walkErr.Error()})
			summary.ErrorCount++
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			summary.Results = append(summary.Results, fileResult{Path: path, Error: infoErr.Error()})
			summary.ErrorCount++
			return nil
		}
		if !info.Mode().IsRegular() {
			summary.Skipped++
			return nil
		}
		if opts.fast && !shouldScanFast(path, info.Size()) {
			summary.Skipped++
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if walkErr != nil {
		return summary, fmt.Errorf("walk target directory: %w", walkErr)
	}

	jobs := make(chan string)
	results := make(chan fileResult)
	workers := defaultWorkers()
	if workers > len(paths) {
		workers = len(paths)
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				result := scanOne(path)
				results <- result
			}
		}()
	}
	go func() {
		for _, path := range paths {
			jobs <- path
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	completed := 0
	color := supportsColor(stdout)
	for result := range results {
		if result.Error != "" {
			summary.ErrorCount++
		}
		if result.Suspicious {
			summary.FindingCount++
		}
		if opts.verbose {
			if result.Error != "" {
				fmt.Fprintf(stdout, "%s %s: %s\n", style("Error", colorRed, color), result.Path, result.Error)
			} else {
				fmt.Fprintf(stdout, "%s %s\n", style("Scanned", colorMuted, color), result.Path)
			}
		} else {
			completed++
			fmt.Fprint(stdout, "\r", renderProgress(completed, len(paths), summary.FindingCount, color))
		}
		summary.Results = append(summary.Results, result)
	}
	if !opts.verbose && len(paths) > 0 {
		fmt.Fprintln(stdout)
	}
	sort.Slice(summary.Results, func(i, j int) bool {
		return summary.Results[i].Path < summary.Results[j].Path
	})
	summary.Duration = time.Since(started)
	return summary, nil
}

func scanOne(path string) fileResult {
	result := fileResult{Path: path}
	native, err := scanNative(path)
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
	if native.Entropy >= entropyThreshold && native.Size >= 4096 {
		result.Suspicious = true
		result.Reasons = append(result.Reasons, fmt.Sprintf("high entropy (%.3f bits/byte)", native.Entropy))
	}
	return result
}

var criticalExtensions = map[string]struct{}{
	".exe": {}, ".dll": {}, ".so": {}, ".dylib": {}, ".bin": {},
	".sh": {}, ".bash": {}, ".py": {}, ".php": {}, ".js": {},
	".ps1": {}, ".bat": {}, ".cmd": {}, ".vbs": {}, ".jar": {},
	".elf": {}, ".com": {}, ".scr": {},
}

var mediaExtensions = map[string]struct{}{
	".jpg": {}, ".jpeg": {}, ".png": {}, ".gif": {}, ".webp": {},
	".mp3": {}, ".mp4": {}, ".m4a": {}, ".mov": {}, ".avi": {},
	".mkv": {}, ".wav": {}, ".flac": {}, ".ogg": {}, ".heic": {},
}

func shouldScanFast(path string, size int64) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if _, media := mediaExtensions[ext]; media && size > mediaSkipSize {
		return false
	}
	_, critical := criticalExtensions[ext]
	return critical
}

func validateSummary(s scanSummary) error {
	for _, result := range s.Results {
		if result.Path == "" {
			return errors.New("scan result contains an empty path")
		}
	}
	return nil
}
