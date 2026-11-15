package inputfiles

import (
	"fmt"
	"strings"
	"testing"
)

func BenchmarkSheet(b *testing.B) {
	var rows strings.Builder
	for i := 1; rows.Len() < 16<<20; i++ {
		fmt.Fprintf(&rows, `<row r="%d"><c r="A%d" s="1"><v>%d</v></c><c r="B%d" t="s"><v>0</v></c><c r="C%d"><v>12.5</v></c></row>`, i, i, i, i, i)
	}
	data := workbook(b, "", rows.String(), "xl/sharedStrings.xml", `<sst><si><t>name</t></si></sst>`)
	b.SetBytes(int64(rows.Len()))
	b.ResetTimer()
	for range b.N {
		if _, err := extractOffice(data, officeSpreadsheet, nil); err != nil {
			b.Fatal(err)
		}
	}
}
