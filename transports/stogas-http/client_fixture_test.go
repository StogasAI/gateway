package stogashttp

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
	"github.com/maximhq/bifrost/transports/stogas/confidential/channel"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
)

// The compiled test binary can host the real request pipeline for external SDK
// conformance. Synthetic hardware is confined to this test binary. Production
// startup and the hardware-verification suites never accept this fixture.
func TestMain(m *testing.M) {
	if err := installFixtureCatalog(); err != nil {
		fmt.Fprintln(os.Stderr, "client conformance catalog failed:", err)
		os.Exit(1)
	}
	fixture := os.Getenv("STOGAS_CLIENT_FIXTURE_BOOT")
	if fixture == "" {
		os.Exit(m.Run())
	}
	if err := serveClientFixture(fixture); err != nil {
		fmt.Fprintln(os.Stderr, "client conformance fixture failed:", err)
		os.Exit(1)
	}
}

func installFixtureCatalog() error {
	dir := os.Getenv("STOGAS_CLIENT_FIXTURE_CATALOG_DIR")
	if dir == "" {
		dir = "../stogas/catalog/fallback"
	}
	runtimeData, err := os.ReadFile(filepath.Join(dir, "catalog.runtime.json"))
	if err != nil {
		return err
	}
	publicData, err := os.ReadFile(filepath.Join(dir, "catalog.public.json"))
	if err != nil {
		return err
	}
	return catalog.InstallApproved(runtimeData, publicData, catalog.Identity{
		Sequence: 1,
		Digest:   fmt.Sprintf("sha256:%x", sha256.Sum256(runtimeData)),
	}, fmt.Sprintf("sha256:%x", sha256.Sum256(publicData)))
}

func serveClientFixture(path string) error {
	config, err := stogas.LoadFromEnv()
	if err != nil {
		return err
	}
	flag.StringVar(&config.Host, "host", "127.0.0.1", "fixture host")
	flag.StringVar(&config.Port, "port", config.Port, "fixture port")
	flag.StringVar(&config.PrivateReadinessPort, "private-readiness-port", config.PrivateReadinessPort, "fixture readiness")
	flag.StringVar(&config.LogLevel, "log-level", config.LogLevel, "fixture log level")
	flag.StringVar(&config.LogOutputStyle, "log-style", config.LogOutputStyle, "fixture log style")
	flag.Parse()
	if address := net.ParseIP(config.Host); address == nil || !address.IsLoopback() || config.Confidential.Enabled {
		return fmt.Errorf("client fixture requires a non-confidential loopback listener")
	}
	logger := bifrost.NewDefaultLogger(schemas.LogLevel(config.LogLevel))
	logger.SetOutputType(schemas.LoggerOutputType(config.LogOutputStyle))
	server, err := New(context.Background(), config, logger)
	if err != nil {
		return err
	}
	defer server.shutdown()
	encoded, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var fixture struct {
		Record attest.BootRecord `json:"record"`
	}
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		return err
	}
	document, err := fixture.Record.Document()
	if err != nil {
		return err
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), bytes.Repeat([]byte{42}, 32))
	if err != nil {
		return err
	}
	server.proofs, err = proofhttp.New(document, key)
	if err != nil {
		return err
	}
	defer server.proofs.Close()
	report, err := base64.RawURLEncoding.DecodeString(fixture.Record.Report)
	if err != nil {
		return err
	}
	server.sessionNodeID = attest.SNPNodeID([32]byte(report[0x140:0x160]))
	batcher, err := attest.NewBatcher(new(sessionTestAttester), server.memory.confidentialReservation(quoteRetainedBytes))
	if err != nil {
		return err
	}
	defer batcher.Close(context.Background())
	setup, err := channel.NewServerSetup(attest.Production, attest.BootEvidence{Document: document, Inclusion: []byte(`{}`)}, 10*time.Minute, batcher)
	if err != nil {
		return err
	}
	server.sessions, err = channel.NewStore(setup, server.memory.confidentialReservation(encryptedSessionRetainedBytes))
	if err != nil {
		return err
	}
	defer server.sessions.Close()
	return server.Start()
}
