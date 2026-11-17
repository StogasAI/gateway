package inputfiles

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/maximhq/bifrost/transports/stogas/inputfiles/filetype"
)

// pdfFile reports whether an inline document is a PDF: one that declares the type, or one that
// declares no type or only application/octet-stream and whose filename ends in .pdf. Either
// holds the PDF signature where readers look for it.
func pdfFile(declared, payload, filename string) bool {
	switch strings.ToLower(declared) {
	case filetype.PDFMediaType, "application/x-pdf":
	case "", "application/octet-stream":
		if !strings.EqualFold(path.Ext(filename), ".pdf") {
			return false
		}
	default:
		return false
	}
	return bytes.Contains(head(payload), []byte("%PDF-"))
}

// Bounds of the work that one PDF may cause. A PDF is a program for its reader: fonts, filters
// and a page language. So a separate program reads it, stogas-pdftext, which gives up every
// system call but output and memory before it parses a byte. These bounds are the arguments of
// that program, and the gateway checks again whatever it writes.
const (
	pdfPages = 2000
	// pdfTextBytes is the bound of an Office file's text.
	pdfTextBytes = officeTextBytes
	// pdfMemoryBytes bounds the reader's address space. The largest of the measured files, a
	// 492-page standard, needs about 400 MiB.
	pdfMemoryBytes = 1 << 30
	// pdfSeconds bounds the processor time of one file, and twice that its time on the clock.
	// The slowest measured file that is not a loop, 492 pages, takes four seconds.
	pdfSeconds = 20
)

const (
	errPDFUnreadable = readError("is not a readable PDF")
	errPDFPages      = readError("has more than 2,000 pages, which is the most that text extraction reads")
	errPDFText       = readError("holds more than the 8 MiB of text that text extraction reads")
	errPDFPassword   = readError("needs a password")
	errPDFMemory     = readError("needs more than the 1 GiB of memory that text extraction gives a PDF")
	errPDFSeconds    = readError("takes more than the 20 seconds that text extraction gives a PDF")
	errPDFScanned    = readError("is a PDF without text, such as a scan")
)

// ErrPDFBusy refuses a PDF while every reader has been busy for as long as one file may take.
var ErrPDFBusy = errors.New("PDF text extraction is busy")

// ErrPDFUnavailable is a failure of the reader itself, not of the file.
var ErrPDFUnavailable = errors.New("PDF text extraction is unavailable")

// pdfReader is the path of the program that reads PDFs. The release image holds it beside the
// gateway; STOGAS_PDFTEXT names it elsewhere.
var pdfReader = sync.OnceValue(func() string {
	if path := os.Getenv("STOGAS_PDFTEXT"); path != "" {
		return path
	}
	return "/stogas/pdftext"
})

// pdfReaders bounds the readers that run at once to half the processors, which also bounds their
// memory: each takes a processor and up to pdfMemoryBytes outside the gateway's own memory.
var pdfReaders = make(chan struct{}, max(1, runtime.GOMAXPROCS(0)/2))

// The exit statuses of stogas-pdftext.
const (
	pdfExitUnreadable = iota + 1
	pdfExitPages
	pdfExitText
	pdfExitPassword
	pdfExitMemory
	pdfExitNotConfined
)

// extractPDF returns the text of a PDF's pages, each under a heading with its number.
func extractPDF(file []byte) (string, error) {
	wait := time.NewTimer(pdfSeconds * time.Second)
	defer wait.Stop()
	select {
	case pdfReaders <- struct{}{}:
		defer func() { <-pdfReaders }()
	case <-wait.C:
		return "", capacityError{ErrPDFBusy}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*pdfSeconds*time.Second)
	defer cancel()
	reader := exec.CommandContext(ctx, pdfReader(),
		strconv.Itoa(pdfPages), strconv.Itoa(pdfTextBytes), strconv.Itoa(pdfMemoryBytes), strconv.Itoa(pdfSeconds))
	// The reader gets no environment and, as every descriptor of the gateway closes on exec,
	// only its three pipes.
	reader.Env = []string{}
	reader.Stdin = bytes.NewReader(file)
	reader.Stderr = io.Discard
	out, err := reader.StdoutPipe()
	if err != nil {
		return "", ErrPDFUnavailable
	}
	if err := reader.Start(); err != nil {
		return "", ErrPDFUnavailable
	}
	text, readErr := pdfPagesText(out)
	if readErr != nil {
		// Stop a reader whose output the gateway refuses. One that has ended keeps its status.
		_ = reader.Process.Kill()
		_, _ = io.Copy(io.Discard, out)
	}
	err = reader.Wait()
	var exit *exec.ExitError
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		return "", errPDFSeconds
	case readErr != nil && readErr != errPDFUnreadable, err == nil:
		// A bound that the output passed, a file without text, or the text.
		return text, readErr
	case !errors.As(err, &exit):
		return "", ErrPDFUnavailable
	}
	// The kernel ends a reader that passes its processor time with SIGXCPU.
	if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() && status.Signal() == syscall.SIGXCPU {
		return "", errPDFSeconds
	}
	switch exit.ExitCode() {
	case pdfExitPages:
		return "", errPDFPages
	case pdfExitText:
		return "", errPDFText
	case pdfExitPassword:
		return "", errPDFPassword
	case pdfExitMemory:
		return "", errPDFMemory
	case pdfExitNotConfined:
		return "", ErrPDFUnavailable
	}
	// Any other end is the parser's: a file that it refuses, or one that crashes it.
	return "", errPDFUnreadable
}

// pdfPagesText reads the reader's output, each page as a length in four little-endian bytes and
// then its text, within the bounds that the reader was given. The reader is untrusted once it
// has parsed the file, so nothing here relies on it keeping them.
func pdfPagesText(out io.Reader) (string, error) {
	in := bufio.NewReader(out)
	var text strings.Builder
	var page []byte
	pages, written, empty := 0, 0, true
	for {
		var length [4]byte
		if _, err := io.ReadFull(in, length[:]); err == io.EOF {
			break
		} else if err != nil {
			return "", errPDFUnreadable
		}
		size := int(binary.LittleEndian.Uint32(length[:]))
		pages++
		written += size
		if pages > pdfPages {
			return "", errPDFPages
		}
		if size > pdfTextBytes || written > pdfTextBytes {
			return "", errPDFText
		}
		if cap(page) < size {
			page = make([]byte, size)
		}
		page = page[:size]
		if _, err := io.ReadFull(in, page); err != nil || !utf8.Valid(page) {
			return "", errPDFUnreadable
		}
		if pages > 1 {
			text.WriteString("\n\n")
		}
		text.WriteString("## Page " + strconv.Itoa(pages) + "\n\n")
		if content := bytes.TrimSpace(page); len(content) > 0 {
			empty = false
			text.Write(content)
		} else {
			// The model then knows that the page holds something that is not text.
			text.WriteString("[This page has no text]")
		}
	}
	if pages == 0 {
		return "", errPDFUnreadable
	}
	if empty {
		return "", errPDFScanned
	}
	return text.String(), nil
}
