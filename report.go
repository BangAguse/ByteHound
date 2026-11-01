package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func writeReport(path string, summary scanSummary) error {
	if err := validateSummary(summary); err != nil {
		return err
	}
	var data []byte
	var err error
	switch strings.ToLower(filepath.Ext(path)) {
	case ".txt":
		data = []byte(formatText(summary))
	case ".json":
		data, err = json.MarshalIndent(summary, "", "  ")
		if err == nil {
			data = append(data, '\n')
		}
	case ".csv":
		data, err = formatCSV(summary)
	case ".pdf":
		data = formatPDF(summary)
	default:
		return fmt.Errorf("unsupported report extension %q; use .txt, .json, .pdf, or .csv", filepath.Ext(path))
	}
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write %q: %w", path, err)
	}
	return nil
}

func formatText(s scanSummary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\nAuthor: %s | GitHub: %s\n", appName, appVersion, author, githubUsername)
	fmt.Fprintf(&b, "Target: %s\nStarted: %s\nDuration: %s\nScanned: %d | Findings: %d | Skipped: %d | Errors: %d\n\n",
		s.Root, s.StartedAt.Format("2006-01-02T15:04:05Z07:00"), s.Duration.Round(1e6),
		len(s.Results)-s.ErrorCount, s.FindingCount, s.Skipped, s.ErrorCount)
	b.WriteString("Heuristic results (not a malware verdict):\n")
	for _, result := range s.Results {
		state := "No bundled heuristic matched"
		if result.Suspicious {
			state = strings.Join(result.Reasons, "; ")
		}
		if result.Error != "" {
			state = "ERROR: " + result.Error
		}
		fmt.Fprintf(&b, "- %s | %s | %d bytes | entropy %.3f | matches %d\n",
			result.Path, state, result.Size, result.Entropy, result.Matches)
	}
	return b.String()
}

func formatCSV(s scanSummary) ([]byte, error) {
	var b strings.Builder
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"path", "size_bytes", "entropy_bits_per_byte", "signature_matches", "signature", "suspicious", "reasons", "error"}); err != nil {
		return nil, err
	}
	for _, r := range s.Results {
		record := []string{
			r.Path, fmt.Sprint(r.Size), fmt.Sprintf("%.6f", r.Entropy), fmt.Sprint(r.Matches),
			r.Signature, fmt.Sprint(r.Suspicious), strings.Join(r.Reasons, "; "), r.Error,
		}
		if err := w.Write(record); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}
