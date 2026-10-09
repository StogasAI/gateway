package stogashttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	verifier "github.com/StogasAI/verifier/go"
	ref "github.com/StogasAI/verifier/go/reference"
	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
	"github.com/maximhq/bifrost/transports/stogas/confidential/channel"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proofhttp"
)

// fixtureNode rebuilds the synthetic boot vector from its public seeds: 32 bytes
// of 42 for signing and bytes 0 through 31 for provisioning.
func fixtureNode(path string) (*verifier.NodeKeys, []byte, string, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, "", err
	}
	var fixture struct {
		Record struct {
			GatewayReleaseID     string `json:"gateway_release_id"`
			HardwarePolicySHA256 string `json:"hardware_policy_sha256"`
			Report               string `json:"report"`
			ReportData           struct {
				RegistrationChallenge string `json:"registration_challenge"`
				TLSSPKISHA256         string `json:"tls_spki_sha256"`
			} `json:"report_data"`
		} `json:"record"`
	}
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		return nil, nil, "", err
	}
	digests := make([][32]byte, 4)
	for i, value := range []string{fixture.Record.ReportData.TLSSPKISHA256, fixture.Record.ReportData.RegistrationChallenge, fixture.Record.GatewayReleaseID, fixture.Record.HardwarePolicySHA256} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			return nil, nil, "", fmt.Errorf("invalid boot fixture digest")
		}
		digests[i] = [32]byte(decoded)
	}
	report, err := base64.RawURLEncoding.DecodeString(fixture.Record.Report)
	if err != nil || len(report) != 0x4a0 {
		return nil, nil, "", fmt.Errorf("invalid boot fixture report")
	}
	seeds := bytes.Repeat([]byte{42}, 32)
	for i := range 32 {
		seeds = append(seeds, byte(i))
	}
	keys, err := verifier.GenerateNodeKeys(bytes.NewReader(seeds))
	if err != nil {
		return nil, nil, "", err
	}
	document, err := keys.BootDocument(byte(attest.Production), digests[0], digests[1], report, digests[2], digests[3])
	if err != nil {
		keys.Close()
		return nil, nil, "", err
	}
	return keys, document, ref.SNPNodeID([32]byte(report[0x140:0x160])), nil
}

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
	keys, document, nodeID, err := fixtureNode(path)
	if err != nil {
		return err
	}
	defer keys.Close()
	server.proofs, err = proofhttp.New(sha256.Sum256(document), nodeID, keys)
	if err != nil {
		return err
	}
	defer server.proofs.Close()
	server.sessionNodeID = nodeID
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
