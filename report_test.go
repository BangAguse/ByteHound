package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReportEncoders(t *testing.T) {
	summary := scanSummary{
		Root: "/tmp/evidence", StartedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Results:      []fileResult{{Path: `sample (1).js`, Size: 12, Entropy: 3.25, Matches: 1, Signature: "test", Suspicious: true, Reasons: []string{"matched"}}},
		FindingCount: 1,
	}
	t.Run("json", func(t *testing.T) {
		encoded, err := json.Marshal(summary)
		if err != nil {
			t.Fatal(err)
		}
		var decoded scanSummary
		if err := json.Unmarshal(encoded, &decoded); err != nil || len(decoded.Results) != 1 || decoded.Results[0].Path != summary.Results[0].Path {
			t.Fatalf("JSON report did not round-trip: %#v, %v", decoded, err)
		}
	})
	t.Run("csv", func(t *testing.T) {
		encoded, err := formatCSV(summary)
		if err != nil {
			t.Fatal(err)
		}
		records, err := csv.NewReader(bytes.NewReader(encoded)).ReadAll()
		if err != nil || len(records) != 2 || records[1][0] != summary.Results[0].Path {
			t.Fatalf("invalid CSV report: %v, %v", records, err)
		}
	})
	t.Run("pdf", func(t *testing.T) {
		encoded := formatPDF(summary)
		if !bytes.HasPrefix(encoded, []byte("%PDF-1.4")) || !bytes.Contains(encoded, []byte("%%EOF")) || !bytes.Contains(encoded, []byte(`sample \(1\).js`)) {
			t.Fatal("PDF report is missing its header, escaped path, or trailer")
		}
	})
	t.Run("text", func(t *testing.T) {
		text := formatText(summary)
		if !strings.Contains(text, "not a malware verdict") || !strings.Contains(text, summary.Results[0].Path) {
			t.Fatal("text report is missing required content")
		}
	})
}

func TestFastScanFilter(t *testing.T) {
	if !shouldScanFast("a.PY", 1) {
		t.Fatal("critical extension should be selected case-insensitively")
	}
	if shouldScanFast("photo.jpg", mediaSkipSize+1) {
		t.Fatal("large media file should be skipped")
	}
	if shouldScanFast("photo.jpg", mediaSkipSize) {
		t.Fatal("media extension should not be selected in fast mode")
	}
	if shouldScanFast("notes.txt", 1) {
		t.Fatal("non-critical extension should not be selected in fast mode")
	}
}

func TestParseOptionsRejectsUnsupportedOutput(t *testing.T) {
	if _, err := parseOptions([]string{"--output", "report.xml"}); err == nil {
		t.Fatal("expected unsupported report format to fail")
	}
}

func TestHelpSeparatesAuthorAndGitHubIdentity(t *testing.T) {
	var output bytes.Buffer
	printHelp(&output)
	help := output.String()
	if !strings.Contains(help, "Author: "+author) || !strings.Contains(help, "GitHub: "+githubUsername) {
		t.Fatal("help output must label the author's real name and GitHub username separately")
	}
}

func TestBannerContainsArtAndCorrectIdentity(t *testing.T) {
	var output bytes.Buffer
	printBanner(&output)
	banner := output.String()
	for _, expected := range []string{"-ByteHound-", "ByteHound", "Author: " + author, "GitHub: BangAguse"} {
		if !strings.Contains(banner, expected) {
			t.Errorf("banner is missing %q", expected)
		}
	}
	if strings.Contains(banner, "BAngAguse") {
		t.Fatal("banner contains the previous username typo")
	}
}

func TestProgressUIAndColorFallback(t *testing.T) {
	line := renderProgress(2, 4, 1, false)
	if !strings.Contains(line, "2/4 files") || !strings.Contains(line, "1 finding") || strings.Contains(line, "\033[") {
		t.Fatalf("unexpected plain progress output: %q", line)
	}
	if got := style("label", colorTeal, false); got != "label" {
		t.Fatalf("color-disabled style should be plain text, got %q", got)
	}
	if got := renderProgress(4, 4, 0, true); !strings.Contains(got, "\033[") {
		t.Fatalf("color-enabled progress should include ANSI styling, got %q", got)
	}
}

func TestWriteReportFormats(t *testing.T) {
	dir := t.TempDir()
	summary := scanSummary{
		Root: "/tmp/evidence", StartedAt: time.Now(),
		Results: []fileResult{{Path: "sample.js", Size: 4}},
	}
	for _, extension := range []string{".txt", ".json", ".csv", ".pdf"} {
		path := filepath.Join(dir, "report"+extension)
		if err := writeReport(path, summary); err != nil {
			t.Errorf("writeReport(%s): %v", extension, err)
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			t.Errorf("report %s is missing or empty: %v", extension, err)
		}
	}
}
