package attest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	DefaultTSMReportRoot = "/sys/kernel/config/tsm/report"
	DefaultSEVGuestPath  = "/dev/sev-guest"
	EnvelopeSchemaV1     = "stogas.sev-snp-quote-envelope.v1"
	ProviderSEVGuest     = "sev_guest"
)

type Attester interface {
	Quote(ctx context.Context, reportData [64]byte) ([]byte, error)
}

type Envelope struct {
	Schema       string `json:"schema"`
	Provider     string `json:"provider"`
	Report       string `json:"report"`
	AuxBlob      string `json:"auxblob,omitempty"`
	ManifestBlob string `json:"manifestblob,omitempty"`
}

type ConfigFS struct {
	Root             string
	NamePrefix       string
	PrivilegeLevel   *int
	ServiceProvider  string
	ReadAuxBlob      bool
	ReadManifestBlob bool
	AllowedProviders []string
	Random           io.Reader
	FileSystem       ConfigFSFileSystem
}

type ConfigFSFileSystem interface {
	Mkdir(name string, perm os.FileMode) error
	ReadFile(name string) ([]byte, error)
	RemoveAll(path string) error
	WriteFile(name string, data []byte, perm os.FileMode) error
}

type osConfigFSFileSystem struct{}

func (osConfigFSFileSystem) Mkdir(name string, perm os.FileMode) error {
	return os.Mkdir(name, perm)
}

func (osConfigFSFileSystem) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (osConfigFSFileSystem) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

func (osConfigFSFileSystem) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(name, data, perm)
}

type Chain []Attester

func DefaultSEVSNP() Chain {
	return Chain{
		ConfigFS{ReadAuxBlob: true, ReadManifestBlob: true},
		SEVGuestDevice{},
	}
}

func (chain Chain) Quote(ctx context.Context, reportData [64]byte) ([]byte, error) {
	var errs []error
	for _, attester := range chain {
		if attester == nil {
			continue
		}
		quote, err := attester.Quote(ctx, reportData)
		if err == nil {
			return quote, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == 0 {
		return nil, errors.New("no attesters configured")
	}
	return nil, errors.Join(errs...)
}

func (a ConfigFS) Quote(ctx context.Context, reportData [64]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	root := a.Root
	if root == "" {
		root = DefaultTSMReportRoot
	}
	fs := a.FileSystem
	if fs == nil {
		fs = osConfigFSFileSystem{}
	}
	name, err := a.reportName()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(root, name)
	if err := fs.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create TSM report instance: %w", err)
	}
	defer func() {
		_ = fs.RemoveAll(dir)
	}()

	generationBefore, err := readGeneration(fs, dir)
	if err != nil {
		return nil, err
	}
	expectedWrites := uint64(0)

	if a.PrivilegeLevel != nil {
		if *a.PrivilegeLevel < 0 || *a.PrivilegeLevel > 3 {
			return nil, errors.New("TSM privlevel must be between 0 and 3")
		}
		if err := fs.WriteFile(filepath.Join(dir, "privlevel"), []byte(strconv.Itoa(*a.PrivilegeLevel)), 0o600); err != nil {
			return nil, fmt.Errorf("write TSM privlevel: %w", err)
		}
		expectedWrites++
	}
	if a.ServiceProvider != "" {
		if err := fs.WriteFile(filepath.Join(dir, "service_provider"), []byte(a.ServiceProvider), 0o600); err != nil {
			return nil, fmt.Errorf("write TSM service_provider: %w", err)
		}
		expectedWrites++
	}
	if err := fs.WriteFile(filepath.Join(dir, "inblob"), reportData[:], 0o600); err != nil {
		return nil, fmt.Errorf("write TSM inblob: %w", err)
	}
	expectedWrites++

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	report, err := fs.ReadFile(filepath.Join(dir, "outblob"))
	if err != nil {
		return nil, fmt.Errorf("read TSM outblob: %w", err)
	}
	if len(report) == 0 {
		return nil, errors.New("TSM outblob is empty")
	}
	providerBytes, err := fs.ReadFile(filepath.Join(dir, "provider"))
	if err != nil {
		return nil, fmt.Errorf("read TSM provider: %w", err)
	}
	provider := strings.TrimSpace(string(providerBytes))
	if provider == "" {
		return nil, errors.New("TSM provider is empty")
	}
	if !providerAllowed(provider, a.AllowedProviders) {
		return nil, fmt.Errorf("unsupported TSM provider %q", provider)
	}

	auxblob, err := readOptionalBlob(fs, dir, "auxblob", a.ReadAuxBlob)
	if err != nil {
		return nil, err
	}
	manifestblob, err := readOptionalBlob(fs, dir, "manifestblob", a.ReadManifestBlob)
	if err != nil {
		return nil, err
	}
	generationAfter, err := readGeneration(fs, dir)
	if err != nil {
		return nil, err
	}
	if generationAfter != generationBefore+expectedWrites {
		return nil, fmt.Errorf("TSM generation changed unexpectedly: before=%d after=%d expected=%d", generationBefore, generationAfter, generationBefore+expectedWrites)
	}

	return EncodeEnvelope(Envelope{
		Schema:       EnvelopeSchemaV1,
		Provider:     provider,
		Report:       base64.RawURLEncoding.EncodeToString(report),
		AuxBlob:      optionalBase64URL(auxblob),
		ManifestBlob: optionalBase64URL(manifestblob),
	})
}

func EncodeEnvelope(envelope Envelope) ([]byte, error) {
	if envelope.Schema == "" {
		envelope.Schema = EnvelopeSchemaV1
	}
	if envelope.Schema != EnvelopeSchemaV1 {
		return nil, fmt.Errorf("unsupported quote envelope schema %q", envelope.Schema)
	}
	if strings.TrimSpace(envelope.Provider) == "" {
		return nil, errors.New("quote envelope provider is required")
	}
	if strings.TrimSpace(envelope.Report) == "" {
		return nil, errors.New("quote envelope report is required")
	}
	return json.Marshal(envelope)
}

func (a ConfigFS) reportName() (string, error) {
	random := a.Random
	if random == nil {
		random = rand.Reader
	}
	prefix := a.NamePrefix
	if prefix == "" {
		prefix = "stogas-"
	}
	var suffix [16]byte
	if _, err := io.ReadFull(random, suffix[:]); err != nil {
		return "", fmt.Errorf("generate TSM report name: %w", err)
	}
	return prefix + hex.EncodeToString(suffix[:]), nil
}

func readGeneration(fs ConfigFSFileSystem, dir string) (uint64, error) {
	bytes, err := fs.ReadFile(filepath.Join(dir, "generation"))
	if err != nil {
		return 0, fmt.Errorf("read TSM generation: %w", err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(bytes)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse TSM generation: %w", err)
	}
	return value, nil
}

func readOptionalBlob(fs ConfigFSFileSystem, dir string, name string, enabled bool) ([]byte, error) {
	if !enabled {
		return nil, nil
	}
	bytes, err := fs.ReadFile(filepath.Join(dir, name))
	if err == nil {
		return bytes, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return nil, fmt.Errorf("read TSM %s: %w", name, err)
}

func optionalBase64URL(bytes []byte) string {
	if len(bytes) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func providerAllowed(provider string, allowed []string) bool {
	if len(allowed) == 0 {
		return provider == ProviderSEVGuest
	}
	for _, value := range allowed {
		if provider == strings.TrimSpace(value) {
			return true
		}
	}
	return false
}
