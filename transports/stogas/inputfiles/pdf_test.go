package inputfiles

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// testPDF builds a PDF with one page for each text, in Helvetica. A password that is not ""
// encrypts it with the standard handler, 40-bit RC4, and that user password; opens says whether
// the empty user password opens an encrypted file, as it does for one that only limits printing.
func testPDF(encrypted, opens bool, pages ...string) []byte {
	var out bytes.Buffer
	offsets := []int{}
	object := func(body string) {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", len(offsets), body)
	}
	padding, _ := hex.DecodeString("28bf4e5e4e758a4164004e56fffa01082e2e00b6d0683e802f0ca9fe6453697a")
	pad := func(password string) []byte { return append([]byte(password), padding...)[:32] }
	id := []byte("stogas-test-file")
	user := ""
	if !opens {
		user = "secret"
	}
	ownerKey := md5.Sum(pad("owner"))
	owner := make([]byte, 32)
	cipher, _ := rc4.NewCipher(ownerKey[:5])
	cipher.XORKeyStream(owner, pad(user))
	keySum := md5.Sum(append(append(append(pad(user), owner...), 0xfc, 0xff, 0xff, 0xff), id...))
	key := keySum[:5]
	userEntry := make([]byte, 32)
	cipher, _ = rc4.NewCipher(key)
	cipher.XORKeyStream(userEntry, padding)

	kids := make([]string, len(pages))
	for i := range pages {
		kids[i] = strconv.Itoa(4+2*i) + " 0 R"
	}
	object("<< /Type /Catalog /Pages 2 0 R >>")
	object("<< /Type /Pages /Count " + strconv.Itoa(len(pages)) + " /Kids [" + strings.Join(kids, " ") + "] >>")
	object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	for i, text := range pages {
		object("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents " + strconv.Itoa(5+2*i) + " 0 R >>")
		content := []byte{}
		if text != "" {
			content = []byte("BT /F1 12 Tf 72 720 Td (" + strings.NewReplacer(`\`, `\\`, "(", `\(`, ")", `\)`).Replace(text) + ") Tj ET")
		}
		if encrypted {
			number := len(offsets) + 1
			sum := md5.Sum(append(append([]byte{}, key...), byte(number), byte(number>>8), byte(number>>16), 0, 0))
			cipher, _ := rc4.NewCipher(sum[:10])
			cipher.XORKeyStream(content, content)
		}
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n<< /Length %d >>\nstream\n", len(offsets), len(content))
		out.Write(content)
		out.WriteString("\nendstream\nendobj\n")
	}
	trailer := ""
	if encrypted {
		object("<< /Filter /Standard /V 1 /R 2 /P -4 /O <" + hex.EncodeToString(owner) + "> /U <" + hex.EncodeToString(userEntry) + "> >>")
		trailer = " /Encrypt " + strconv.Itoa(len(offsets)) + " 0 R /ID [<" + hex.EncodeToString(id) + "> <" + hex.EncodeToString(id) + ">]"
	}
	head := append([]byte("%PDF-1.4\n"), out.Bytes()...)
	start := len(head)
	table := fmt.Sprintf("xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, offset := range offsets {
		table += fmt.Sprintf("%010d 00000 n \n", offset+len("%PDF-1.4\n"))
	}
	return append(head, []byte(table+"trailer\n<< /Size "+strconv.Itoa(len(offsets)+1)+" /Root 1 0 R"+trailer+" >>\nstartxref\n"+strconv.Itoa(start)+"\n%%EOF\n")...)
}

func TestPDFText(t *testing.T) {
	text, err := extractPDF(testPDF(false, true, "Invoice 4471 (paid)", "", `Total: 12\50`))
	if want := "## Page 1\n\nInvoice 4471 (paid)\n\n## Page 2\n\n[This page has no text]\n\n## Page 3\n\nTotal: 12\\50"; err != nil || text != want {
		t.Fatalf("got %q, %v; want %q", text, err, want)
	}
	// A file that only limits printing opens with the empty password, as in a viewer.
	if text, err := extractPDF(testPDF(true, true, "Board minutes")); err != nil || text != "## Page 1\n\nBoard minutes" {
		t.Fatalf("an encrypted file that opens without a password: %q, %v", text, err)
	}
	many := make([]string, pdfPages+1)
	for i := range many {
		many[i] = "x"
	}
	// 1,000 pages of 10,000 bytes each are more than the 8 MiB.
	long := make([]string, 1000)
	for i := range long {
		long[i] = strings.Repeat("word ", 2000)
	}
	for name, test := range map[string]struct {
		file []byte
		want error
	}{
		"a password":            {testPDF(true, false, "Board minutes"), errPDFPassword},
		"pages without text":    {testPDF(false, true, "", " "), errPDFScanned},
		"more pages":            {testPDF(false, true, many...), errPDFPages},
		"more text":             {testPDF(false, true, long...), errPDFText},
		"a truncated file":      {testPDF(false, true, "Invoice")[:60], errPDFUnreadable},
		"bytes that are no PDF": {[]byte("%PDF-1.7\nnothing that a reader can parse"), errPDFUnreadable},
		"no bytes":              {nil, errPDFUnreadable},
	} {
		if text, err := extractPDF(test.file); err != test.want || text != "" {
			t.Errorf("%s: got %.40q, %v; want %v", name, text, err, test.want)
		}
	}
}

// The reader is untrusted once it has parsed a file, so the gateway checks its output against
// the bounds that it was given.
func TestPDFReaderOutputIsChecked(t *testing.T) {
	frame := func(text string) string {
		return string(binary.LittleEndian.AppendUint32(nil, uint32(len(text)))) + text
	}
	for name, test := range map[string]struct {
		out  string
		want error
	}{
		"more pages than the bound": {strings.Repeat(frame("x"), pdfPages+1), errPDFPages},
		"more text than the bound":  {frame(strings.Repeat("x", pdfTextBytes/2)) + frame(strings.Repeat("x", pdfTextBytes/2+1)), errPDFText},
		"a length without its text": {string([]byte{0xff, 0xff, 0xff, 0x7f}) + "x", errPDFText},
		"a page that ends early":    {frame("whole") + frame("cut")[:5], errPDFUnreadable},
		"a length that ends early":  {frame("whole") + "\x01\x00", errPDFUnreadable},
		"text that is not UTF-8":    {frame("\xff\xfe"), errPDFUnreadable},
		"no pages":                  {"", errPDFUnreadable},
	} {
		if text, err := pdfPagesText(strings.NewReader(test.out)); err != test.want || text != "" {
			t.Errorf("%s: got %d bytes, %v; want %v", name, len(text), err, test.want)
		}
	}
}

// The reader gives up its system calls before it reads the file: the kernel reports the filter
// while the reader still waits for its first byte.
func TestPDFReaderConfinesItselfBeforeItReadsTheFile(t *testing.T) {
	reader := exec.Command(pdfReader(), strconv.Itoa(pdfPages), strconv.Itoa(pdfTextBytes), strconv.Itoa(pdfMemoryBytes), strconv.Itoa(pdfSeconds))
	in, err := reader.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	reader.Stdout = &out
	if err := reader.Start(); err != nil {
		t.Fatalf("%v. Tests need the reader that stogas/scripts/go.sh builds, named by STOGAS_PDFTEXT", err)
	}
	defer func() { _ = reader.Process.Kill() }()
	status := ""
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		raw, err := os.ReadFile("/proc/" + strconv.Itoa(reader.Process.Pid) + "/status")
		if err != nil {
			t.Fatal(err)
		}
		if status = string(raw); strings.Contains(status, "Seccomp:\t2") {
			break
		}
	}
	// Mode 2 is a filter. Without new privileges, no program that the reader could start gets
	// more rights than it has, and it can start none.
	if !strings.Contains(status, "Seccomp:\t2") || !strings.Contains(status, "NoNewPrivs:\t1") {
		t.Fatalf("the waiting reader is not confined:\n%s", status)
	}
	limits, err := os.ReadFile("/proc/" + strconv.Itoa(reader.Process.Pid) + "/limits")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Max address space " + strconv.Itoa(pdfMemoryBytes) + " " + strconv.Itoa(pdfMemoryBytes),
		"Max cpu time " + strconv.Itoa(pdfSeconds) + " " + strconv.Itoa(pdfSeconds+1),
		"Max core file size 0 0",
	} {
		if !strings.Contains(strings.Join(strings.Fields(string(limits)), " "), want) {
			t.Fatalf("the waiting reader lacks the limit %q:\n%s", want, limits)
		}
	}
	if _, err := in.Write(testPDF(false, true, "Read under the filter")); err != nil {
		t.Fatal(err)
	}
	in.Close()
	if err := reader.Wait(); err != nil {
		t.Fatal(err)
	}
	if text, err := pdfPagesText(&out); err != nil || text != "## Page 1\n\nRead under the filter" {
		t.Fatalf("got %q, %v", text, err)
	}
}

// Extracted text holds no NUL, as a text file that becomes text holds none.
func TestPDFTextLeavesOutNUL(t *testing.T) {
	frame := func(text string) string {
		return string(binary.LittleEndian.AppendUint32(nil, uint32(len(text)))) + text
	}
	if text, err := pdfPagesText(strings.NewReader(frame("To\x00tal") + frame("\x00"))); err != nil || text != "## Page 1\n\nTotal\n\n## Page 2\n\n[This page has no text]" {
		t.Fatalf("got %q, %v", text, err)
	}
}

// Whatever the reader writes, the gateway returns pages within the bounds or a refusal.
func FuzzPDFReaderOutput(f *testing.F) {
	f.Add([]byte("\x05\x00\x00\x00hello\x00\x00\x00\x00"))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{2, 0, 0, 0, 0xff, 0xfe})
	f.Fuzz(func(t *testing.T, out []byte) {
		text, err := pdfPagesText(bytes.NewReader(out))
		switch {
		case err != nil && text != "":
			t.Fatalf("a refusal came with text: %v", err)
		case err == nil && (!utf8.ValidString(text) || !strings.HasPrefix(text, "## Page 1\n\n") || len(text) > 2*len(out)+64*pdfPages):
			t.Fatalf("pages outside the bounds: %.80q", text)
		}
	})
}
