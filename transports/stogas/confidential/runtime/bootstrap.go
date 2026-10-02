package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	verifier "github.com/StogasAI/verifier/go"
	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
	"github.com/maximhq/bifrost/transports/stogas/confidential/identity"
	"github.com/maximhq/bifrost/transports/stogas/confidential/provision"
	secretstore "github.com/maximhq/bifrost/transports/stogas/confidential/secrets"
)

type preparedBoot struct {
	record   attest.BootRecord
	document []byte
	identity verifier.BootIdentity
}

type bootCompletion struct {
	boot     attest.BootEvidence
	identity verifier.BootIdentity
	region   provision.Region
}

type quotedBoot struct {
	data        attest.BootReportData
	report      string
	measurement string
}

// quoteBoot runs once per registration challenge. Evidence delivery retries keep
// this report; they never create periodic hardware quotes or new boot identities.
func quoteBoot(ctx context.Context, environment string, material *identity.Material, challenge string, reporter attest.Attester) (*quotedBoot, error) {
	data := attest.BootReportData{
		Schema: attest.BootReportDataSchema, Environment: environment,
		RegistrationChallenge: challenge, TLSSPKISHA256: material.TLSSPKISHA256,
		SigningPublicKey: material.SigningPublicKey, HPKEPublicKey: material.HPKEPublicKey,
	}
	commitment, err := data.Commitment()
	if err != nil {
		return nil, err
	}
	quoted, err := reporter.Quote(ctx, commitment)
	if err != nil {
		return nil, err
	}
	if len(quoted) > 256*1024 {
		return nil, errors.New("local quote exceeds its bound")
	}
	measurement, err := attest.MeasurementHex(quoted)
	if err != nil {
		return nil, err
	}
	var envelope attest.Envelope
	if err := json.Unmarshal(quoted, &envelope); err != nil {
		return nil, err
	}
	return &quotedBoot{data: data, report: envelope.Report, measurement: measurement}, nil
}

// prepare appraises retained hardware evidence before its first registration.
func (q *quotedBoot) prepare(ctx context.Context, evidence *currentEvidence) (*preparedBoot, error) {
	challengeBytes, err := hex.DecodeString(q.data.RegistrationChallenge)
	if err != nil || len(challengeBytes) != 32 {
		return nil, errors.New("invalid registration challenge")
	}
	var result *preparedBoot
	err = evidence.refresh(ctx, func(snapshot *verifier.EvidenceSnapshot, summary evidenceSummary) error {
		gateway, ok := summary.gateway(q.measurement)
		if !ok {
			return &verifier.VerificationError{Code: "not_approved", Message: "running measurement is not approved"}
		}
		record := attest.BootRecord{
			Schema: attest.BootSchema, GatewayReleaseID: gateway.ID,
			HardwarePolicySHA256: summary.Approvals.HardwarePolicySHA256, Report: q.report, ReportData: q.data,
		}
		document, err := record.Document()
		if err != nil {
			return err
		}
		checked, err := snapshot.VerifyRegistrationAt(document, [32]byte(challengeBytes), evidence.now())
		if err != nil {
			return err
		}
		result = &preparedBoot{record: record, document: document, identity: checked}
		return nil
	})
	return result, err
}

// installBootCompletion never interprets Control's ready reply as attestation.
// It verifies the exact logged document locally, authenticates the sealed payload,
// validates the Web PKI chain/key, and then installs one immutable secret set.
func installBootCompletion(boot *preparedBoot, response *provision.RegistrationResponse, snapshot *verifier.EvidenceSnapshot, now time.Time, material *identity.Material, certs *identity.CertificateStore, secrets *secretstore.Store, hostname string) (*bootCompletion, error) {
	if boot == nil || response == nil || response.Status != "ready" || response.NodeID != boot.identity.NodeID || response.Provisioning == nil {
		return nil, errors.New("registration is not complete for this boot")
	}
	checked, err := snapshot.VerifyLoggedBootAt(boot.document, response.Inclusion, now)
	if err != nil {
		return nil, err
	}
	if checked.NodeID != boot.identity.NodeID || checked.BootSHA256 != boot.identity.BootSHA256 {
		return nil, errors.New("logged boot identity differs")
	}
	opened, err := response.Provisioning.Open(material.HPKEPrivateKey, sha256.Sum256(boot.document))
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range opened.Secrets {
			opened.Secrets[i].Plaintext = ""
		}
	}()
	if _, err := certs.InstallBootChain([]byte(opened.CertificatePEM), hostname); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCertificateInstruction, err)
	}
	if err := secrets.InstallBoot(opened.Secrets); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSecretReleaseInstallation, err)
	}
	return &bootCompletion{
		boot:     attest.BootEvidence{Document: append([]byte(nil), boot.document...), Inclusion: append([]byte(nil), response.Inclusion...)},
		identity: checked,
		region:   opened.Region,
	}, nil
}
