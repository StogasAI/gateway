package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	document []byte
	identity verifier.BootIdentity
}

type bootCompletion struct {
	boot     attest.BootEvidence
	identity verifier.BootIdentity
	region   provision.Region
}

type quotedBoot struct {
	challenge   [32]byte
	report      []byte
	measurement string
}

// quoteBoot runs once per registration challenge. Evidence delivery retries keep
// this report; they never create periodic hardware quotes or new boot identities.
func quoteBoot(ctx context.Context, environment attest.Environment, material *identity.Material, keys *verifier.NodeKeys, challenge string, reporter attest.Attester) (*quotedBoot, error) {
	decoded, err := hex.DecodeString(challenge)
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("invalid registration challenge")
	}
	data, err := keys.ReportData(byte(environment), material.TLSSPKISHA256, [32]byte(decoded))
	if err != nil {
		return nil, err
	}
	quoted, err := reporter.Quote(ctx, data)
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
	report, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Report)
	if err != nil {
		return nil, err
	}
	return &quotedBoot{challenge: [32]byte(decoded), report: report, measurement: measurement}, nil
}

// prepare appraises retained hardware evidence before its first registration.
func (q *quotedBoot) prepare(ctx context.Context, evidence *currentEvidence, environment attest.Environment, material *identity.Material, keys *verifier.NodeKeys) (*preparedBoot, error) {
	var result *preparedBoot
	err := evidence.refresh(ctx, func(snapshot *verifier.EvidenceSnapshot, summary evidenceSummary) error {
		gateway, ok := summary.gateway(q.measurement)
		if !ok {
			return &verifier.VerificationError{Code: "not_approved", Message: "running measurement is not approved"}
		}
		release, err := hexDigest(gateway.ID)
		if err != nil {
			return err
		}
		policy, err := hexDigest(summary.Approvals.HardwarePolicySHA256)
		if err != nil {
			return err
		}
		document, err := keys.BootDocument(byte(environment), material.TLSSPKISHA256, q.challenge, q.report, release, policy)
		if err != nil {
			return err
		}
		checked, err := snapshot.VerifyRegistrationAt(document, q.challenge, evidence.now())
		if err != nil {
			return err
		}
		result = &preparedBoot{document: document, identity: checked}
		return nil
	})
	return result, err
}

func hexDigest(value string) ([32]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != value {
		return [32]byte{}, errors.New("invalid approved digest")
	}
	return [32]byte(decoded), nil
}

// installBootCompletion never interprets Control's ready reply as attestation.
// It verifies the exact logged document locally, authenticates the sealed payload,
// validates the Web PKI chain/key, and then installs one immutable secret set.
func installBootCompletion(boot *preparedBoot, response *provision.RegistrationResponse, snapshot *verifier.EvidenceSnapshot, now time.Time, keys *verifier.NodeKeys, certs *identity.CertificateStore, secrets *secretstore.Store, hostname string) (*bootCompletion, error) {
	if boot == nil || response == nil || response.Status != "ready" || response.NodeID != boot.identity.NodeID || len(response.Provisioning) == 0 {
		return nil, errors.New("registration is not complete for this boot")
	}
	checked, err := snapshot.VerifyLoggedBootAt(boot.document, response.Inclusion, now)
	if err != nil {
		return nil, err
	}
	if checked.NodeID != boot.identity.NodeID || checked.BootSHA256 != boot.identity.BootSHA256 {
		return nil, errors.New("logged boot identity differs")
	}
	// Opening erases the provisioning key; all later Control calls return public data.
	plaintext, err := keys.OpenProvisioning(sha256.Sum256(boot.document), response.Provisioning)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	opened, err := provision.ParseBootSecrets(plaintext)
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
