package attest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestConfigFSQuoteBuildsEnvelopeAndCleansUpReportInstance(t *testing.T) {
	fs := newFakeConfigFS()
	var reportData [64]byte
	for i := range reportData {
		reportData[i] = byte(i)
	}
	privlevel := 2
	quote, err := ConfigFS{
		Root:             "/config/tsm/report",
		NamePrefix:       "node-",
		PrivilegeLevel:   &privlevel,
		ServiceProvider:  "svsm",
		ReadAuxBlob:      true,
		ReadManifestBlob: true,
		Random:           bytes.NewReader([]byte("0123456789abcdef")),
		FileSystem:       fs,
	}.Quote(context.Background(), reportData)
	if err != nil {
		t.Fatal(err)
	}

	var envelope Envelope
	if err := json.Unmarshal(quote, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != EnvelopeSchemaV1 {
		t.Fatalf("unexpected schema: %s", envelope.Schema)
	}
	if envelope.Provider != ProviderSEVGuest {
		t.Fatalf("unexpected provider: %s", envelope.Provider)
	}
	assertBase64URL(t, "report", envelope.Report, []byte("sev-snp-report"))
	assertBase64URL(t, "auxblob", envelope.AuxBlob, []byte("cert-table"))
	assertBase64URL(t, "manifestblob", envelope.ManifestBlob, []byte("manifest"))

	dir := "/config/tsm/report/node-30313233343536373839616263646566"
	report := fs.reports[dir]
	if report == nil {
		t.Fatalf("expected report dir %s to be created", dir)
	}
	if string(report.files["privlevel"]) != "2" {
		t.Fatalf("privlevel was not written: %q", report.files["privlevel"])
	}
	if string(report.files["service_provider"]) != "svsm" {
		t.Fatalf("service_provider was not written: %q", report.files["service_provider"])
	}
	if !bytes.Equal(report.files["inblob"], reportData[:]) {
		t.Fatalf("inblob did not receive report data")
	}
	if report.generation != 3 {
		t.Fatalf("expected generation to account for three writes, got %d", report.generation)
	}
	if !fs.removed[dir] {
		t.Fatalf("report instance was not cleaned up")
	}
}

func TestConfigFSQuoteUnwrapsReportBlobEnvelope(t *testing.T) {
	fs := newFakeConfigFS()
	report := make([]byte, snpReportSize)
	binary.LittleEndian.PutUint32(report[0:4], snpReportVersionMin)
	binary.LittleEndian.PutUint32(report[0x34:0x38], snpReportSigAlgo)
	report[0x50] = 0xaa
	wrapped := make([]byte, 0x20+len(report))
	binary.LittleEndian.PutUint32(wrapped[4:8], uint32(len(report)))
	copy(wrapped[0x20:], report)
	fs.outblob = wrapped

	quote, err := ConfigFS{
		Root:       "/config/tsm/report",
		Random:     bytes.NewReader([]byte("0123456789abcdef")),
		FileSystem: fs,
	}.Quote(context.Background(), [64]byte{})
	if err != nil {
		t.Fatal(err)
	}

	var envelope Envelope
	if err := json.Unmarshal(quote, &envelope); err != nil {
		t.Fatal(err)
	}
	assertBase64URL(t, "report", envelope.Report, report)
}

func TestNormalizeReportBlobDoesNotUnwrapInvalidFirmwarePayload(t *testing.T) {
	wrapped := make([]byte, 0x20+snpReportSize)
	binary.LittleEndian.PutUint32(wrapped[4:8], snpReportSize)

	normalized := NormalizeReportBlob(wrapped)
	if !bytes.Equal(normalized, wrapped) {
		t.Fatal("invalid firmware payload was unwrapped")
	}
}

func TestConfigFSRejectsUnsupportedProviderAndCleansUp(t *testing.T) {
	fs := newFakeConfigFS()
	fs.provider = "tdx_guest"
	_, err := ConfigFS{
		Root:       "/config/tsm/report",
		Random:     bytes.NewReader([]byte("0123456789abcdef")),
		FileSystem: fs,
	}.Quote(context.Background(), [64]byte{})
	if err == nil || !strings.Contains(err.Error(), "unsupported TSM provider") {
		t.Fatalf("expected unsupported provider error, got %v", err)
	}
	if !fs.removed["/config/tsm/report/stogas-30313233343536373839616263646566"] {
		t.Fatalf("report instance was not cleaned up after provider rejection")
	}
}

func TestConfigFSRejectsGenerationConflict(t *testing.T) {
	fs := newFakeConfigFS()
	fs.conflictAfterOutblob = true
	_, err := ConfigFS{
		Root:       "/config/tsm/report",
		Random:     bytes.NewReader([]byte("0123456789abcdef")),
		FileSystem: fs,
	}.Quote(context.Background(), [64]byte{})
	if err == nil || !strings.Contains(err.Error(), "generation changed unexpectedly") {
		t.Fatalf("expected generation conflict, got %v", err)
	}
}

func TestConfigFSHonorsContextBeforeCreatingReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fs := newFakeConfigFS()
	_, err := ConfigFS{
		Root:       "/config/tsm/report",
		Random:     bytes.NewReader([]byte("0123456789abcdef")),
		FileSystem: fs,
	}.Quote(ctx, [64]byte{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if len(fs.reports) != 0 {
		t.Fatalf("context-canceled quote created report instances")
	}
}

func TestChainUsesFallbackAttester(t *testing.T) {
	expected := []byte("quote")
	chain := Chain{
		AttesterFunc(func(ctx context.Context, reportData [64]byte) ([]byte, error) {
			return nil, errors.New("configfs unavailable")
		}),
		AttesterFunc(func(ctx context.Context, reportData [64]byte) ([]byte, error) {
			return expected, nil
		}),
	}
	actual, err := chain.Quote(context.Background(), [64]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("unexpected fallback quote: %q", actual)
	}
}

func TestEncodeEnvelopeValidatesRequiredFields(t *testing.T) {
	if _, err := EncodeEnvelope(Envelope{Provider: ProviderSEVGuest}); err == nil {
		t.Fatal("expected missing report to fail")
	}
	if _, err := EncodeEnvelope(Envelope{Report: "cmVwb3J0"}); err == nil {
		t.Fatal("expected missing provider to fail")
	}
	if _, err := EncodeEnvelope(Envelope{Schema: "wrong", Provider: ProviderSEVGuest, Report: "cmVwb3J0"}); err == nil {
		t.Fatal("expected wrong schema to fail")
	}
}

type AttesterFunc func(ctx context.Context, reportData [64]byte) ([]byte, error)

func (f AttesterFunc) Quote(ctx context.Context, reportData [64]byte) ([]byte, error) {
	return f(ctx, reportData)
}

type fakeConfigFS struct {
	provider             string
	outblob              []byte
	reports              map[string]*fakeReport
	removed              map[string]bool
	conflictAfterOutblob bool
}

type fakeReport struct {
	files       map[string][]byte
	generation  uint64
	outblobRead bool
}

func newFakeConfigFS() *fakeConfigFS {
	return &fakeConfigFS{
		provider: ProviderSEVGuest,
		reports:  map[string]*fakeReport{},
		removed:  map[string]bool{},
	}
}

func (fs *fakeConfigFS) Mkdir(name string, perm os.FileMode) error {
	if _, exists := fs.reports[name]; exists {
		return os.ErrExist
	}
	outblob := fs.outblob
	if len(outblob) == 0 {
		outblob = []byte("sev-snp-report")
	}
	fs.reports[name] = &fakeReport{
		files: map[string][]byte{
			"auxblob":      []byte("cert-table"),
			"manifestblob": []byte("manifest"),
			"outblob":      append([]byte(nil), outblob...),
			"provider":     []byte(fs.provider),
		},
	}
	return nil
}

func (fs *fakeConfigFS) ReadFile(name string) ([]byte, error) {
	report, base, err := fs.lookup(name)
	if err != nil {
		return nil, err
	}
	if base == "generation" {
		value := report.generation
		if fs.conflictAfterOutblob && report.outblobRead {
			value++
		}
		return []byte(strconv.FormatUint(value, 10)), nil
	}
	value, ok := report.files[base]
	if !ok {
		return nil, os.ErrNotExist
	}
	if base == "outblob" {
		report.outblobRead = true
	}
	return append([]byte(nil), value...), nil
}

func (fs *fakeConfigFS) RemoveAll(path string) error {
	fs.removed[path] = true
	return nil
}

func (fs *fakeConfigFS) WriteFile(name string, data []byte, perm os.FileMode) error {
	report, base, err := fs.lookup(name)
	if err != nil {
		return err
	}
	switch base {
	case "inblob", "privlevel", "service_provider":
		report.files[base] = append([]byte(nil), data...)
		report.generation++
		return nil
	default:
		return os.ErrPermission
	}
}

func (fs *fakeConfigFS) lookup(name string) (*fakeReport, string, error) {
	dir := filepath.Dir(name)
	base := filepath.Base(name)
	report, ok := fs.reports[dir]
	if !ok {
		if report, ok = fs.reports[name]; ok {
			return report, "", nil
		}
		return nil, "", os.ErrNotExist
	}
	return report, base, nil
}

func assertBase64URL(t *testing.T, name string, value string, expected []byte) {
	t.Helper()
	actual, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("%s is not base64url: %v", name, err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("unexpected %s: %q", name, actual)
	}
}
