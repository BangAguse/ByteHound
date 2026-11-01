package main

import (
	"bytes"
	"fmt"
	"strings"
)

func formatPDF(s scanSummary) []byte {
	lines := strings.Split(formatText(s), "\n")
	const linesPerPage = 58
	if len(lines) == 0 {
		lines = []string{appName}
	}
	pages := make([][]string, 0, (len(lines)+linesPerPage-1)/linesPerPage)
	for start := 0; start < len(lines); start += linesPerPage {
		end := start + linesPerPage
		if end > len(lines) {
			end = len(lines)
		}
		pages = append(pages, lines[start:end])
	}

	objectCount := 3 + 2*len(pages)
	objects := make([][]byte, objectCount+1)
	objects[1] = []byte("<< /Type /Catalog /Pages 2 0 R >>")
	var kids strings.Builder
	for i := range pages {
		fmt.Fprintf(&kids, "%d 0 R ", 4+2*i)
	}
	objects[2] = []byte(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kids.String(), len(pages)))
	objects[3] = []byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	for i, pageLines := range pages {
		pageID, contentID := 4+2*i, 5+2*i
		var content strings.Builder
		content.WriteString("BT\n/F1 9 Tf\n50 790 Td\n12 TL\n")
		for _, line := range pageLines {
			fmt.Fprintf(&content, "(%s) Tj\nT*\n", escapePDFText(line))
		}
		content.WriteString("ET\n")
		stream := content.String()
		objects[pageID] = []byte(fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>",
			contentID,
		))
		objects[contentID] = []byte(fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(stream), stream))
	}

	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offsets := make([]int, objectCount+1)
	for id := 1; id <= objectCount; id++ {
		offsets[id] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n", id)
		out.Write(objects[id])
		out.WriteString("\nendobj\n")
	}
	xrefOffset := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", objectCount+1)
	for id := 1; id <= objectCount; id++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[id])
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", objectCount+1, xrefOffset)
	return out.Bytes()
}

func escapePDFText(text string) string {
	var b strings.Builder
	for _, r := range text {
		if r < 32 || r > 126 {
			b.WriteByte('?')
			continue
		}
		if r == '(' || r == ')' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
