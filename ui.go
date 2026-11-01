package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	colorReset = "\033[0m"
	colorBold  = "\033[1m"
	colorTeal  = "\033[38;5;73m"
	colorMuted = "\033[38;5;245m"
	colorGreen = "\033[38;5;114m"
	colorAmber = "\033[38;5;179m"
	colorRed   = "\033[38;5;167m"
)

func supportsColor(w io.Writer) bool {
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled || os.Getenv("TERM") == "dumb" {
		return false
	}
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func style(text, color string, enabled bool) string {
	if !enabled {
		return text
	}
	return color + text + colorReset
}

func printBanner(w io.Writer) {
	color := supportsColor(w)
	art := []string{
		"                    ,",
		"               ,.  | \\",
		"              |: \\ ; :\\",
		"              :' ;\\| ::\\",
		"               \\ : | `::\\",
		"               _)  |   `:.",
		"             ,' , `.    ;: ;",
		"           ,' ;:  ;\"'  ,:: |_",
		"          /,   ` .    ;::: |:`-.__",
		"       _,' _o\\  ,::.`:' ;  ;   . '",
		"   _,-'           `:.          ;\"\"\\,",
		",-'                     ,:         `-;,",
		"\\,                       ;:           ;--._",
		" `.______,-,----._     ,' ;:        ,/ ,  ,`",
		"        / /,-';'  \\     ; `:      ,'/,::.:::",
		"      ,',;-'-'_,--;    ;   :.   ,',',;::::::",
		"     ( /___,-'     `.     ;::,,'o/  ,:::::::",
		"      `'             )    ;:,'o /  ;\"-   -::",
		"                     \\__ _,'o ,'         ,::",
		"                        ) `--'       ,..::::",
		"     -ByteHound-        ; `.        ,:::::::",
		"                         ;  `::.    :::::::",
	}
	for _, line := range art {
		fmt.Fprintf(w, "%s\n", style(line, colorTeal, color))
	}
	fmt.Fprintf(w, "\n%s %s\n", style(appName, colorBold+colorTeal, color), style(appVersion, colorMuted, color))
	fmt.Fprintf(w, "Author: %s  GitHub: %s\n\n", author, githubUsername)
}

func printScanStart(w io.Writer, root string, fast bool) {
	color := supportsColor(w)
	fmt.Fprintf(w, "%s %s\n", style("Scanning", colorTeal, color), root)
	if fast {
		fmt.Fprintf(w, "%s\n", style("Fast mode", colorMuted, color))
	}
}

func renderProgress(done, total, findings int, color bool) string {
	const width = 20
	filled := 0
	if total > 0 {
		filled = done * width / total
	}
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("━", filled) + strings.Repeat("─", width-filled)
	countLabel := "findings"
	if findings == 1 {
		countLabel = "finding"
	}
	return fmt.Sprintf("%s %s/%s files  %s %d %s",
		style("["+bar+"]", colorTeal, color),
		style(fmt.Sprint(done), colorBold, color),
		fmt.Sprint(total),
		style("·", colorMuted, color),
		findings,
		countLabel)
}

func printScanSummary(w io.Writer, s scanSummary) {
	color := supportsColor(w)
	heading := "Scan complete"
	if s.ErrorCount > 0 {
		heading = "Scan complete with errors"
	}
	fmt.Fprintf(w, "\n%s\n", style(heading, colorBold+colorTeal, color))
	fmt.Fprintf(w, "  %s %s\n", style(fmt.Sprintf("%-10s", "Target"), colorMuted, color), s.Root)
	fmt.Fprintf(w, "  %s %d\n", style(fmt.Sprintf("%-10s", "Scanned"), colorMuted, color), len(s.Results)-s.ErrorCount)
	fmt.Fprintf(w, "  %s %s\n", style(fmt.Sprintf("%-10s", "Findings"), colorMuted, color), findingCount(s.FindingCount, color))
	fmt.Fprintf(w, "  %s %d\n", style(fmt.Sprintf("%-10s", "Skipped"), colorMuted, color), s.Skipped)
	fmt.Fprintf(w, "  %s %s\n", style(fmt.Sprintf("%-10s", "Errors"), colorMuted, color), errorCount(s.ErrorCount, color))
	fmt.Fprintf(w, "  %s %s\n", style(fmt.Sprintf("%-10s", "Duration"), colorMuted, color), s.Duration.Round(1e6))
	if s.FindingCount > 0 {
		fmt.Fprintf(w, "\n%s\n", style("Heuristic findings", colorAmber, color))
		for _, result := range s.Results {
			if result.Suspicious {
				fmt.Fprintf(w, "  %s  %s\n", style("!", colorAmber, color), result.Path)
				for _, reason := range result.Reasons {
					fmt.Fprintf(w, "     %s\n", style(reason, colorMuted, color))
				}
			}
		}
	} else {
		fmt.Fprintf(w, "\n%s\n", style("No bundled indicators found.", colorGreen, color))
	}
	fmt.Fprintf(w, "\n%s\n", style("Heuristic results are indicators, not a malware verdict.", colorMuted, color))
}

func findingCount(count int, color bool) string {
	text, shade := fmt.Sprint(count), colorGreen
	if count > 0 {
		shade = colorAmber
	}
	return style(text, shade, color)
}

func errorCount(count int, color bool) string {
	text, shade := fmt.Sprint(count), colorGreen
	if count > 0 {
		shade = colorRed
	}
	return style(text, shade, color)
}
