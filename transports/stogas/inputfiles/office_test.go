package inputfiles

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/inputfiles/filetype"
)

// The files in testdata/office were written by python-docx, python-pptx and openpyxl, whose
// templates come from Word, PowerPoint and Excel, by odfpy, and by LibreOffice Calc (orders.xlsx
// and orders.ods). Each .txt beside one is the text that it must give.
func TestOfficeFilesGiveTheirText(t *testing.T) {
	files, err := filepath.Glob("testdata/office/*")
	if err != nil || len(files) != 14 {
		t.Fatalf("testdata is incomplete: %v, %v", files, err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, ".txt") {
			continue
		}
		t.Run(filepath.Base(name), func(t *testing.T) {
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(name + ".txt")
			if err != nil {
				t.Fatal(err)
			}
			retained := 0
			got, err := extractOffice(data, officeMediaTypes[officeExtensions[filepath.Ext(name)]], func(bytes int) error {
				retained += bytes
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if got+"\n" != string(want) {
				t.Fatalf("wrong text:\n%s", got)
			}
			if retained < 7*len(got) {
				t.Fatalf("admitted %d bytes for %d bytes of text", retained, len(got))
			}
		})
	}
}

// archive builds a zip archive of the parts, in the order given.
func archive(t testing.TB, parts ...string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for i := 0; i < len(parts); i += 2 {
		part, err := writer.Create(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(parts[i+1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

const (
	packageRels = `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="%s"/></Relationships>`
	wordOpen    = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n" + `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" xmlns:v="urn:schemas-microsoft-com:vml"><w:body>`
	wordClose   = `</w:body></w:document>`
	sheetOpen   = `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`
	sheetClose  = `</sheetData></worksheet>`
)

func rels(target string) string { return strings.Replace(packageRels, "%s", target, 1) }

// word builds a Word file with the body and further parts.
func word(t testing.TB, body string, parts ...string) []byte {
	return archive(t, append([]string{"[Content_Types].xml", "<Types/>", "_rels/.rels", rels("word/document.xml"), "word/document.xml", wordOpen + body + wordClose}, parts...)...)
}

// workbook builds an Excel file with one sheet named Data and further parts.
func workbook(t testing.TB, properties, rows string, parts ...string) []byte {
	const relationships = `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>` +
		`<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="/xl/styles.xml"/>` +
		`<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/chartsheet" Target="chartsheets/sheet1.xml"/>` +
		`</Relationships>`
	main := `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` + properties +
		`<sheets><sheet name="Chart" sheetId="2" r:id="rId4"/><sheet name="Data" sheetId="1" r:id="rId1"/></sheets></workbook>`
	return archive(t, append([]string{"_rels/.rels", rels("/xl/workbook.xml"), "xl/workbook.xml", main, "xl/_rels/workbook.xml.rels", relationships, "xl/worksheets/sheet1.xml", sheetOpen + rows + sheetClose}, parts...)...)
}

func TestWordTextFollowsTheDocument(t *testing.T) {
	styles := `<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:style w:type="paragraph" w:styleId="berschrift2"><w:name w:val="heading 2"/></w:style>` +
		`<w:style w:type="paragraph" w:styleId="Aufzhlung"><w:name w:val="List Bullet"/><w:pPr><w:numPr><w:numId w:val="1"/></w:numPr></w:pPr></w:style></w:styles>`
	documentRels := `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footnotes" Target="footnotes.xml"/>` +
		`<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/endnotes" Target="endnotes.xml"/>` +
		`<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com/" TargetMode="External"/></Relationships>`
	notes := func(kind string) string {
		return `<w:` + kind + `s xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
			`<w:` + kind + ` w:type="separator" w:id="-1"><w:p><w:r><w:t>separator</w:t></w:r></w:p></w:` + kind + `>` +
			`<w:` + kind + ` w:id="2"><w:p><w:r><w:t>A ` + kind + `.</w:t></w:r></w:p><w:p><w:r><w:t>Its second paragraph.</w:t></w:r></w:p></w:` + kind + `></w:` + kind + `s>`
	}
	body := `<w:p><w:pPr><w:pStyle w:val="berschrift2"/></w:pPr><w:r><w:t>Überschrift</w:t></w:r></w:p>` +
		// A tracked change: the inserted text is the document's, the deleted text is not.
		`<w:p><w:r><w:t xml:space="preserve">Kept </w:t></w:r><w:ins><w:r><w:t>inserted</w:t></w:r></w:ins><w:del><w:r><w:delText>deleted</w:delText></w:r></w:del>` +
		`<w:moveFrom><w:r><w:t>moved away</w:t></w:r></w:moveFrom><w:r><w:footnoteReference w:id="2"/></w:r><w:r><w:endnoteReference w:id="2"/></w:r></w:p>` +
		// A paragraph whose earlier style was a heading.
		`<w:p><w:pPr><w:pPrChange><w:pPr><w:pStyle w:val="berschrift2"/></w:pPr></w:pPrChange></w:pPr><w:r><w:t>Plain &amp; &lt;escaped&gt;</w:t></w:r><w:r><w:instrText>HYPERLINK "x"</w:instrText></w:r></w:p>` +
		`<w:p><w:pPr><w:pStyle w:val="Aufzhlung"/></w:pPr><w:r><w:t>Styled item</w:t></w:r></w:p>` +
		`<w:p><w:pPr><w:numPr><w:ilvl w:val="1"/><w:numId w:val="3"/></w:numPr></w:pPr><w:r><w:t>Numbered item</w:t></w:r></w:p>` +
		// A text box holds paragraphs inside a paragraph, once for Word 2010 and once for older readers.
		`<w:p><w:r><w:t>Around</w:t></w:r><w:r><mc:AlternateContent><mc:Choice Requires="wps"><wps:txbx><w:txbxContent><w:p><w:r><w:t>In the box</w:t></w:r></w:p></w:txbxContent></wps:txbx></mc:Choice>` +
		`<mc:Fallback><w:pict><v:textbox><w:txbxContent><w:p><w:r><w:t>In the box</w:t></w:r></w:p></w:txbxContent></v:textbox></w:pict></mc:Fallback></mc:AlternateContent></w:r></w:p>` +
		`<w:tbl><w:tr><w:tc><w:p><w:r><w:t>A</w:t></w:r></w:p><w:p><w:r><w:t>second</w:t></w:r></w:p></w:tc><w:tc><w:p/></w:tc></w:tr>` +
		`<w:tr><w:tc><w:tbl><w:tr><w:tc><w:p><w:r><w:t>inner 1</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>inner 2</w:t></w:r></w:p></w:tc></w:tr></w:tbl><w:p/></w:tc></w:tr></w:tbl>` +
		`<w:sectPr><w:headerReference w:type="default"/></w:sectPr>`
	got, err := extractOffice(word(t, body, "word/_rels/document.xml.rels", documentRels, "word/styles.xml", styles, "word/footnotes.xml", notes("footnote"), "word/endnotes.xml", notes("endnote")), officeDocument, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "## Überschrift\n\nKept inserted[^2][^e2]\n\nPlain & <escaped>\n\n- Styled item\n  - Numbered item\n\nIn the box\n\nAround\n\n" +
		"| A<br>second |  |\n| --- | --- |\n| inner 1 \\| inner 2 |  |\n\n" +
		"[^2]: A footnote.\nIts second paragraph.\n\n[^e2]: A endnote.\nIts second paragraph."
	if got != want {
		t.Fatalf("wrong text:\n%q\nwant\n%q", got, want)
	}
}

// The reader takes the XML that Office parts hold and refuses the rest, most of all a document
// type declaration, whose entities are how XML expands without bound.
func TestOfficeXMLReadsWhatPartsHold(t *testing.T) {
	read := func(source string) (string, error) {
		x, err := newOfficeXML([]byte(source))
		if err != nil {
			return "", err
		}
		var out strings.Builder
		err = x.each(func(token xmlToken) error {
			switch token.kind {
			case xmlStart:
				out.WriteString("<" + string(token.name))
				if id := token.attr("id"); id != "" {
					out.WriteString(" " + id)
				}
				out.WriteString(">")
			case xmlEnd:
				out.WriteString("</" + string(token.name) + ">")
			default:
				out.Write(token.text)
			}
			return nil
		})
		return out.String(), err
	}
	for source, want := range map[string]string{
		"\xef\xbb\xbf<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<a:r xmlns:a=\"x\"><a:t>x</a:t></a:r>\n": "<r><t>x</t></r>",
		`<r><!-- a <comment> --><?pi <x> ?><t><![CDATA[<raw> & ]]]></t></r>`:                                                 "<r><t><raw> & ]</t></r>",
		`<r id="a>b" other='"'><t r:id = 'q&amp;&#x41;&#66;' id="plain"/></r >`:                                              "<r a>b><t q&AB></t></r>",
		`<r>&lt;&gt;&amp;&quot;&apos;&#x1F600;</r>`:                                                                          `<r><>&"'😀</r>`,
	} {
		if got, err := read(source); err != nil || got != want {
			t.Errorf("%q: got %q %v, want %q", source, got, err, want)
		}
	}
	for _, source := range []string{
		`<!DOCTYPE r [<!ENTITY a "aaaa">]><r>&a;</r>`, `<r>&a;</r>`, `<r>&#0;</r>`, `<r>&#xD800;</r>`, `<r>&#x110000;</r>`, `<r>&amp</r>`,
		`<r><t></r></t>`, `<r></r><r></r>`, `<r>`, `</r>`, `text<r/>`, `<r/>text`, `<r a="1></r>`, `<r <t/>></r>`, `<r><![CDATA[x</r>`, `<r><!-- x</r>`,
		`<?xml version="1.0" encoding="ISO-8859-1"?><r/>`, "\xff\xfe<\x00r\x00/\x00>\x00", strings.Repeat("<r>", officeDepth+1),
	} {
		if got, err := read(source); err != errOfficeUnreadable {
			t.Errorf("%q: got %q %v", source, got, err)
		}
	}
}

func TestSheetCellsShowTheirStoredValues(t *testing.T) {
	styles := `<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><numFmts>` +
		`<numFmt numFmtId="164" formatCode="[$-409]d\-mmm\-yy;@"/><numFmt numFmtId="165" formatCode="[h]:mm:ss"/><numFmt numFmtId="166" formatCode="#,##0.00 &quot;days&quot;"/></numFmts>` +
		// A cell style format is not a cell format.
		`<cellStyleXfs><xf numFmtId="14"/></cellStyleXfs>` +
		`<cellXfs><xf numFmtId="0"/><xf numFmtId="14"/><xf numFmtId="164"/><xf numFmtId="165"/><xf numFmtId="166"/><xf numFmtId="20"/></cellXfs></styleSheet>`
	shared := `<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>plain</t></si><si><r><t>rich </t></r><r><t>text</t></r><rPh><t>phonetic</t></rPh></si></sst>`
	rows := `<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>7</v></c><c r="D1" t="inlineStr"><is><t>in, line</t></is></c></row>` +
		// The same serial under a number, a date, a custom date, an elapsed time and a text format.
		`<row r="2"><c r="A2"><v>46082</v></c><c r="B2" s="1"><v>46082</v></c><c r="C2" s="2"><v>46082.75</v></c><c r="D2" s="3"><v>1.5</v></c><c r="E2" s="4"><v>3</v></c><c r="F2" s="5"><v>0.25</v></c></row>` +
		// A formula shows its stored result, an error its code, and a cell without a reference follows the last one.
		`<row r="4"><c r="B4"><f>SUM(A2:A3)</f><v>42</v></c><c t="e"><v>#DIV/0!</v></c><c t="b"><v>1</v></c><c r="XFD4" t="str"><v>last column</v></c><c r="XFE4"><v>past the sheet</v></c></row>` +
		`<row r="5"><c r="A5" s="1"><v>59</v></c><c r="B5" s="1"><v>61</v></c><c r="C5" s="1"><v>-1</v></c><c r="D5" s="1"><v>text</v></c></row>`
	got, err := extractOffice(workbook(t, "", rows, "xl/sharedStrings.xml", shared, "xl/styles.xml", styles), officeSpreadsheet, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "## Data\nplain,rich text,,\"in, line\"\n46082,2026-03-01,2026-03-01T18:00:00,1.5,3,06:00:00\n,42,#DIV/0!,TRUE" + strings.Repeat(",", officeColumns-4) + "last column\n1900-02-28,1900-03-01,-1,text"
	if got != want {
		t.Fatalf("wrong text:\n%.300q\nwant\n%.300q", got, want)
	}
	got, err = extractOffice(workbook(t, `<workbookPr date1904="1"/>`, `<row><c s="1"><v>0</v></c><c s="1"><v>44620</v></c></row>`, "xl/styles.xml", styles), officeSpreadsheet, nil)
	if want := "## Data\n1904-01-01,2026-03-01"; err != nil || got != want {
		t.Fatalf("1904 dates: %q, %v", got, err)
	}
}

func TestDateFormats(t *testing.T) {
	for code, want := range map[string]bool{
		"General": false, "0.00E+00": false, "#,##0.00": false, `"day" 0`: false, "[Red]0": false, "[h]:mm": false, "[mm]:ss": false, `\d0`: false, "@": false,
		"yyyy-mm-dd": true, "DD/MM/YYYY": true, "h:mm AM/PM": true, "[$-F800]dddd, mmmm dd, yyyy": true, "mm:ss.0": true, `0 "h`: false,
	} {
		if got := dateFormat(code); got != want {
			t.Errorf("dateFormat(%q) = %v", code, got)
		}
	}
}

// An archive is untrusted: its directory, the size of its parts and the nesting and amount of
// its XML must stay within the bounds before the gateway holds them.
func TestOfficeArchivesStayWithinBounds(t *testing.T) {
	deep := strings.Repeat("<w:p>", officeDepth)
	for _, tc := range []struct {
		name string
		data []byte
		kind officeKind
		want error
	}{
		{"not an archive", []byte("PK\x03\x04 but nothing else"), officeDocument, errOfficeUnreadable},
		{"no main part", archive(t, "_rels/.rels", rels("word/missing.xml")), officeDocument, errOfficeUnreadable},
		{"no relationships", archive(t, "word/document.xml", wordOpen+wordClose), officeDocument, errOfficeUnreadable},
		{"external main part", archive(t, "_rels/.rels", strings.Replace(rels("word/document.xml"), "/>", ` TargetMode="External"/>`, 1), "word/document.xml", wordOpen+wordClose), officeDocument, errOfficeUnreadable},
		{"another root", archive(t, "_rels/.rels", rels("word/document.xml"), "word/document.xml", "<html/>"), officeDocument, errOfficeUnreadable},
		{"nesting", word(t, deep), officeDocument, errOfficeUnreadable},
		{"unclosed", archive(t, "_rels/.rels", rels("word/document.xml"), "word/document.xml", wordOpen), officeDocument, errOfficeUnreadable},
		{"entity", word(t, `<w:p><w:r><w:t>&bomb;</w:t></w:r></w:p>`), officeDocument, errOfficeUnreadable},
		{"UTF-16", archive(t, "_rels/.rels", rels("word/document.xml"), "word/document.xml", `<?xml version="1.0" encoding="UTF-16"?>`+wordOpen+wordClose), officeDocument, errOfficeUnreadable},
		{"another kind", word(t, ""), officeSpreadsheet, officeError("declares a spreadsheet, but its content is a text document")},
		{"zip64 locator", zip64(word(t, "")), officeDocument, errOfficeTooLarge},
		{"directory away from the end record", directoryOffset(word(t, ""), -1), officeDocument, errOfficeUnreadable},
		{"more text than the bound", word(t, `<w:p><w:r><w:t>`+strings.Repeat("a", officeTextBytes+1)+`</w:t></w:r></w:p>`), officeDocument, errOfficeTooLarge},
		{"more cells than the bound", word(t, `<w:tbl><w:tr>`+strings.Repeat("<w:tc/>", officeTextBytes/4+1)+`</w:tr></w:tbl>`), officeDocument, errOfficeTooLarge},
		{"more commas than the bound", workbook(t, "", strings.Repeat(`<row><c r="XFD1"><v>1</v></c></row>`, officeTextBytes/officeColumns+1)), officeSpreadsheet, errOfficeTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := extractOffice(tc.data, tc.kind, nil); err != tc.want {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("more XML than the bound", func(t *testing.T) {
		// Sixteen parts of 3 MiB of spaces deflate to a few kilobytes each.
		space := strings.Repeat(" ", 3<<20)
		parts := []string{"_rels/.rels", rels("xl/workbook.xml"), "xl/workbook.xml", `<workbook xmlns:r="r"><sheets>` + strings.Repeat(`<sheet name="s" r:id="rId1"/>`, 16) + `</sheets></workbook>`,
			"xl/_rels/workbook.xml.rels", `<Relationships><Relationship Id="rId1" Type="x/worksheet" Target="sheet.xml"/></Relationships>`, "xl/sheet.xml", "<worksheet>" + space + "</worksheet>"}
		data := archive(t, parts...)
		if len(data) > 64<<10 {
			t.Fatalf("the archive is %d bytes", len(data))
		}
		if _, err := extractOffice(data, officeSpreadsheet, nil); err != errOfficeTooLarge {
			t.Fatalf("got %v", err)
		}
	})
	// Cells copy a shared string, so a small sheet can ask for far more text than its XML holds.
	// The reader stops at the bound instead of building what it will refuse.
	for name, rows := range map[string]string{
		"one shared string in many rows": strings.Repeat(`<row><c t="s"><v>0</v></c></row>`, 20000),
		"one shared string across a row": `<row>` + strings.Repeat(`<c t="s"><v>0</v></c>`, 16000) + `</row>`,
	} {
		t.Run(name, func(t *testing.T) {
			data := workbook(t, "", rows, "xl/sharedStrings.xml", `<sst><si><t>`+strings.Repeat("a", 1<<20)+`</t></si></sst>`)
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			if _, err := extractOffice(data, officeSpreadsheet, nil); err != errOfficeTooLarge {
				t.Fatalf("got %v", err)
			}
			runtime.ReadMemStats(&after)
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8*officeTextBytes {
				t.Fatalf("allocated %d MiB before the refusal", allocated>>20)
			}
		})
	}
	t.Run("a part longer than it states", func(t *testing.T) {
		data := word(t, `<w:p><w:r><w:t>`+strings.Repeat("a", 4096)+`</w:t></w:r></w:p>`)
		// The directory entry of word/document.xml states its inflated size 24 bytes in.
		entry := bytes.LastIndex(data, []byte("PK\x01\x02"))
		binary.LittleEndian.PutUint32(data[entry+24:], 64)
		if _, err := extractOffice(data, officeDocument, nil); err != errOfficeUnreadable {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("capacity", func(t *testing.T) {
		capacity := errors.New("capacity")
		_, err := extractOffice(word(t, `<w:p><w:r><w:t>text</w:t></w:r></w:p>`), officeDocument, func(int) error { return capacity })
		if !errors.Is(err, capacity) {
			t.Fatalf("got %v", err)
		}
	})
}

// Part names compare without case, and some Windows libraries write them with backslashes.
func TestOfficePartNamesMatchAsOfficeReadsThem(t *testing.T) {
	data := archive(t, `_RELS\.rels`, rels("word/document.xml"), `Word\Document.XML`, wordOpen+`<w:p><w:r><w:t>Hello</w:t></w:r></w:p>`+wordClose)
	if got, err := extractOffice(data, officeDocument, nil); err != nil || got != "Hello" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// zip64 puts a zip64 end locator before the end record.
func zip64(data []byte) []byte {
	end := bytes.LastIndex(data, []byte("PK\x05\x06"))
	locator := append([]byte("PK\x06\x07"), make([]byte, 16)...)
	return append(append(append([]byte{}, data[:end]...), locator...), data[end:]...)
}

// directoryOffset moves the directory offset that the end record states.
func directoryOffset(data []byte, by int) []byte {
	data = bytes.Clone(data)
	end := bytes.LastIndex(data, []byte("PK\x05\x06"))
	binary.LittleEndian.PutUint32(data[end+16:], uint32(int(binary.LittleEndian.Uint32(data[end+16:]))+by))
	return data
}

func officeRequest(responses bool, mediaType, filename string, data []byte, extra string) map[string]json.RawMessage {
	payload := base64.StdEncoding.EncodeToString(data)
	if mediaType != "" {
		payload = "data:" + mediaType + ";base64," + payload
	}
	if filename != "" {
		extra += `,"filename":"` + filename + `"`
	}
	if responses {
		return map[string]json.RawMessage{"input": json.RawMessage(`[{"role":"user","content":[{"type":"input_file","file_data":"` + payload + `"` + extra + `}]}]`)}
	}
	return map[string]json.RawMessage{"messages": json.RawMessage(`[{"role":"user","content":[{"type":"file","file":{"file_data":"` + payload + `"` + extra + `}}]}]`)}
}

func TestProcessTurnsOfficeFilesIntoText(t *testing.T) {
	const docx = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	file := word(t, `<w:p><w:r><w:t>Hello</w:t></w:r></w:p>`)
	for _, tc := range []struct {
		name                string
		responses           bool
		mediaType, filename string
		data                []byte
		extract             func(filetype.Type) bool
		kept                bool
		want                string
	}{
		{"declared type", false, docx, "note.docx", file, families(filetype.Office), false, `{"text":"note.docx (` + docx + `)\nHello","type":"text"}`},
		{"Responses", true, docx, "", file, families(filetype.Office), false, `{"text":"(` + docx + `)\nHello","type":"input_text"}`},
		{"no type, by its extension", true, "", "Note.DOCX", file, families(filetype.Office), false, `{"text":"Note.DOCX\nHello","type":"input_text"}`},
		{"a zip type, by its extension", false, "application/zip", "note.docx", file, families(filetype.Office), false, `{"text":"note.docx\nHello","type":"text"}`},
		{"the family is off", true, docx, "note.docx", file, families(filetype.Text), false, ""},
		{"the deployment reads it", true, docx, "note.docx", file, families(filetype.Office), true, ""},
		{"no type and no extension", true, "", "note", file, families(filetype.Office), false, ""},
		{"another type with the extension", true, "application/pdf", "note.docx", file, families(filetype.Office), false, ""},
		{"not an archive", true, docx, "note.docx", []byte("Hello"), families(filetype.Office), false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := officeRequest(tc.responses, tc.mediaType, tc.filename, tc.data, "")
			field := "messages"
			if tc.responses {
				field = "input"
			}
			before := string(fields[field])
			stats, err := Process(fields, tc.responses, Options{Extract: tc.extract, File: func(string) (string, bool) { return "", tc.kept }})
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if string(fields[field]) != before || stats.Opaque == "" {
					t.Fatalf("the file did not stay an opaque file: %s, %+v", fields[field], stats)
				}
				return
			}
			var messages []struct {
				Content []map[string]string `json:"content"`
			}
			var want map[string]string
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(fields[field], &messages); err != nil || !reflect.DeepEqual(messages[0].Content[0], want) {
				t.Fatalf("got %s, %v", fields[field], err)
			}
			if stats.Opaque != "" || stats.InlineBytes != len(tc.data) {
				t.Fatalf("wrong quantities: %+v", stats)
			}
		})
	}
}

func TestProcessRefusesOfficeFilesItCannotRead(t *testing.T) {
	const xlsx = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	file := word(t, `<w:p><w:r><w:t>Hello</w:t></w:r></w:p>`)
	for _, tc := range []struct{ name, mediaType, extra, want string }{
		{"another kind", xlsx, "", "input[0].content[0] declares a spreadsheet, but its content is a text document"},
		{"a field that the text cannot keep", "application/vnd.oasis.opendocument.text", `,"detail":"high"`, "input[0].content[0] has detail, which text extraction cannot keep"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := officeRequest(true, tc.mediaType, "book.xlsx", file, tc.extra)
			before := string(fields["input"])
			_, err := Process(fields, true, Options{Extract: families(filetype.Office)})
			var part *PartError
			if !errors.As(err, &part) || err.Error() != tc.want || string(fields["input"]) != before {
				t.Fatalf("got %v", err)
			}
		})
	}
	t.Run("capacity", func(t *testing.T) {
		capacity := errors.New("capacity")
		reserved := 0
		_, err := Process(officeRequest(true, xlsx, "", file, ""), true, Options{Extract: families(filetype.Office), Reserve: func(bytes int) error {
			if reserved = bytes; bytes > len(file)+3 {
				return capacity
			}
			return nil
		}})
		if err != capacity || reserved <= len(file) {
			t.Fatalf("got %v after %d bytes", err, reserved)
		}
	})
}

func FuzzExtractOffice(f *testing.F) {
	files, _ := filepath.Glob("testdata/office/*")
	for _, name := range files {
		if data, err := os.ReadFile(name); err == nil && !strings.HasSuffix(name, ".txt") {
			f.Add(data, uint8(officeMediaTypes[officeExtensions[filepath.Ext(name)]]))
		}
	}
	f.Add(word(f, `<w:tbl><w:tr><w:tc><w:p><w:r><w:t>a</w:t></w:r></w:p></w:tc></w:tr></w:tbl>`), uint8(officeDocument))
	f.Fuzz(func(t *testing.T, data []byte, kind uint8) {
		retained := 0
		text, err := extractOffice(data, officeKind(kind%3+1), func(bytes int) error {
			retained += bytes
			return nil
		})
		if err == nil && (len(text) > officeTextBytes || retained < len(text)) {
			t.Fatalf("%d bytes of text with %d admitted", len(text), retained)
		}
	})
}
