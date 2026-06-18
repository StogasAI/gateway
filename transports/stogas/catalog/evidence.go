package catalog

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const stogasBootstrapPublicKeyDERBase64 = "MCowBQYDK2VwAyEAByVn3LvWVbf3YkokMZPvir70vcDu0nNflgXoM0Y8aQU="
const sigstoreTUFBootstrapRootVersion = 10
const sigstoreTUFBootstrapRootSignedSHA256 = "e708f5c51a3e5168aafe0fb5235be9f711e8f9534f2c4c668e45fa714d900028"
const catalogReleaseWorkflow = ".github/workflows/catalog-release.yml"
const githubAttestationRepository = "StogasAI/stogas-ai"
const githubOIDCIssuer = "https://token.actions.githubusercontent.com"

var fulcioIssuerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
var catalogTagPattern = regexp.MustCompile(`^catalog-v[1-9][0-9]*$`)

type catalogEvidenceBundle struct {
	Catalog           json.RawMessage         `json:"catalog"`
	GithubAttestation githubAttestationBundle `json:"githubAttestation"`
	ReleaseManifest   json.RawMessage         `json:"releaseManifest"`
	Schema            string                  `json:"schema"`
	SigstoreTrust     sigstoreTrustBundle     `json:"sigstoreTrust"`
	StogasSignature   catalogSignature        `json:"stogasSignature"`
	StogasTrust       stogasTrustBundle       `json:"stogasTrust"`
}

type catalogSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	Schema    string `json:"schema"`
	Signature string `json:"signature"`
	Signed    string `json:"signed"`
}

type stogasTrustBundle struct {
	Keys       []stogasTrustKey `json:"keys"`
	Schema     string           `json:"schema"`
	Signatures []struct {
		Algorithm string `json:"algorithm"`
		KeyID     string `json:"keyId"`
		Signature string `json:"signature"`
	} `json:"signatures"`
}

type stogasTrustKey struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	PublicKey struct {
		DERBase64 string `json:"derBase64"`
		Type      string `json:"type"`
	} `json:"publicKey"`
	Purpose             string `json:"purpose"`
	RevokedFromSequence *int   `json:"revokedFromSequence,omitempty"`
	ValidFromSequence   int    `json:"validFromSequence"`
	ValidUntilSequence  *int   `json:"validUntilSequence,omitempty"`
}

type sigstoreTrustBundle struct {
	Metadata struct {
		Snapshot  string `json:"snapshot"`
		Targets   string `json:"targets"`
		Timestamp string `json:"timestamp"`
	} `json:"metadata"`
	RootChain   []string `json:"rootChain"`
	Schema      string   `json:"schema"`
	TrustedRoot string   `json:"trustedRoot"`
}

type tufMetadata struct {
	Signatures []struct {
		KeyID     string `json:"keyid"`
		Signature string `json:"sig"`
	} `json:"signatures"`
	Signed json.RawMessage `json:"signed"`
}

type tufSigned struct {
	Type    string `json:"_type"`
	Expires string `json:"expires"`
	Keys    map[string]struct {
		KeyType string `json:"keytype"`
		KeyVal  struct {
			Public string `json:"public"`
		} `json:"keyval"`
		Scheme string `json:"scheme"`
	} `json:"keys"`
	Meta map[string]struct {
		Hashes  map[string]string `json:"hashes"`
		Length  *int              `json:"length"`
		Version int               `json:"version"`
	} `json:"meta"`
	Roles map[string]struct {
		KeyIDs    []string `json:"keyids"`
		Threshold int      `json:"threshold"`
	} `json:"roles"`
	Targets map[string]struct {
		Hashes map[string]string `json:"hashes"`
		Length int               `json:"length"`
	} `json:"targets"`
	Version int `json:"version"`
}

type sigstoreTrustedRoot struct {
	FulcioChains []struct {
		Certs    []string
		ValidFor validInterval
	}
	RekorKeys map[string]struct {
		KeyDetails string
		SPKI       string
		ValidFor   validInterval
	}
}

type validInterval struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type githubAttestationBundle struct {
	DSSEEnvelope struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			Signature string `json:"sig"`
		} `json:"signatures"`
	} `json:"dsseEnvelope"`
	VerificationMaterial struct {
		Certificate struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificate"`
		TlogEntries []struct {
			CanonicalizedBody string `json:"canonicalizedBody"`
			InclusionPromise  struct {
				SignedEntryTimestamp string `json:"signedEntryTimestamp"`
			} `json:"inclusionPromise"`
			IntegratedTime int64 `json:"integratedTime,string"`
			LogID          struct {
				KeyID string `json:"keyId"`
			} `json:"logId"`
			LogIndex int64 `json:"logIndex,string"`
		} `json:"tlogEntries"`
	} `json:"verificationMaterial"`
}

type inTotoStatement struct {
	Subject []struct {
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
}

type rekorIntotoBody struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Spec       struct {
		Content struct {
			Envelope struct {
				Payload     string `json:"payload"`
				PayloadType string `json:"payloadType"`
				Signatures  []struct {
					Signature string `json:"sig"`
				} `json:"signatures"`
			} `json:"envelope"`
		} `json:"content"`
	} `json:"spec"`
}

type catalogReleaseManifest struct {
	Artifacts map[string]struct {
		SHA256    string `json:"sha256"`
		SizeBytes int    `json:"sizeBytes"`
	} `json:"artifacts"`
	Schema   string `json:"schema"`
	Sequence int    `json:"sequence"`
	Git      struct {
		Repository string `json:"repository"`
		Ref        string `json:"ref"`
		Tag        string `json:"tag"`
	} `json:"git"`
}

func verifyCatalogEvidenceBundle(data []byte) ([]byte, error) {
	var bundle catalogEvidenceBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("decode catalog evidence bundle: %w", err)
	}
	if bundle.Schema != "stogas.evidence.catalog-bundle.v1" {
		return nil, fmt.Errorf("unsupported catalog evidence bundle schema")
	}

	catalogBytes, err := stableJSON(bundle.Catalog)
	if err != nil {
		return nil, fmt.Errorf("canonicalize bundled catalog: %w", err)
	}
	catalogHash := sha256.Sum256(catalogBytes)
	catalogSHA256 := hex.EncodeToString(catalogHash[:])

	var manifest catalogReleaseManifest
	if err := json.Unmarshal(bundle.ReleaseManifest, &manifest); err != nil {
		return nil, fmt.Errorf("decode catalog release manifest: %w", err)
	}
	if manifest.Schema != "stogas.catalog.release.v1" {
		return nil, fmt.Errorf("unsupported catalog release manifest schema")
	}
	artifact, ok := manifest.Artifacts["catalog.json"]
	if !ok {
		return nil, fmt.Errorf("catalog release manifest is missing catalog.json")
	}
	if artifact.SHA256 != catalogSHA256 || artifact.SizeBytes != len(catalogBytes) {
		return nil, fmt.Errorf("catalog hash does not match release manifest")
	}
	if err := verifyStogasCatalogSignature(bundle.ReleaseManifest, bundle.StogasSignature, manifest.Sequence, bundle.StogasTrust); err != nil {
		return nil, err
	}
	trustedRoot, err := verifySigstoreTrustBundle(bundle.SigstoreTrust)
	if err != nil {
		return nil, err
	}
	if err := verifyGitHubAttestation(bundle.GithubAttestation, manifest, catalogSHA256, trustedRoot); err != nil {
		return nil, err
	}
	return catalogBytes, nil
}

func verifyStogasCatalogSignature(manifest json.RawMessage, signature catalogSignature, sequence int, trust stogasTrustBundle) error {
	if signature.Schema != "stogas.catalog.signature.v1" ||
		signature.Algorithm != "Ed25519" ||
		signature.Signed != "release-manifest.json" {
		return fmt.Errorf("unsupported catalog Stogas signature")
	}
	keys, err := verifyStogasTrustBundle(trust)
	if err != nil {
		return err
	}
	key, ok := keys[signature.KeyID]
	if !ok {
		return fmt.Errorf("Stogas release key is not trusted: %s", signature.KeyID)
	}
	if sequence < key.ValidFromSequence {
		return fmt.Errorf("Stogas release key is not valid for this sequence yet")
	}
	if key.ValidUntilSequence != nil && sequence > *key.ValidUntilSequence {
		return fmt.Errorf("Stogas release key expired before this sequence")
	}
	if key.RevokedFromSequence != nil && sequence >= *key.RevokedFromSequence {
		return fmt.Errorf("Stogas release key was revoked for this sequence")
	}
	publicKeyDER, err := base64.StdEncoding.DecodeString(key.PublicKey.DERBase64)
	if err != nil {
		return fmt.Errorf("decode Stogas public key: %w", err)
	}
	publicKeyAny, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return fmt.Errorf("parse Stogas public key: %w", err)
	}
	publicKey, ok := publicKeyAny.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("Stogas public key is not Ed25519")
	}
	sig, err := base64.StdEncoding.DecodeString(signature.Signature)
	if err != nil {
		return fmt.Errorf("decode Stogas catalog signature: %w", err)
	}
	manifestBytes, err := stableJSON(manifest)
	if err != nil {
		return fmt.Errorf("canonicalize catalog release manifest: %w", err)
	}
	payload := append([]byte("stogas catalog release v1\n"), manifestBytes...)
	if !ed25519.Verify(publicKey, payload, sig) {
		return fmt.Errorf("catalog Stogas signature is invalid")
	}
	return nil
}

func verifyStogasTrustBundle(trust stogasTrustBundle) (map[string]stogasTrustKey, error) {
	if trust.Schema != "stogas.trust.v1" {
		return nil, fmt.Errorf("unsupported Stogas trust schema")
	}
	payload, err := stogasTrustPayload(trust)
	if err != nil {
		return nil, err
	}
	verified := false
	for _, signature := range trust.Signatures {
		if signature.KeyID != "stogas-ed25519-stamp-v1" || signature.Algorithm != "Ed25519" {
			continue
		}
		publicKeyDER, err := base64.StdEncoding.DecodeString(stogasBootstrapPublicKeyDERBase64)
		if err != nil {
			return nil, fmt.Errorf("decode Stogas bootstrap key: %w", err)
		}
		publicKeyAny, err := x509.ParsePKIXPublicKey(publicKeyDER)
		if err != nil {
			return nil, fmt.Errorf("parse Stogas bootstrap key: %w", err)
		}
		publicKey, ok := publicKeyAny.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("Stogas bootstrap key is not Ed25519")
		}
		sig, err := base64.StdEncoding.DecodeString(signature.Signature)
		if err != nil {
			return nil, fmt.Errorf("decode Stogas trust signature: %w", err)
		}
		if ed25519.Verify(publicKey, payload, sig) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("Stogas trust bundle is not signed by a bootstrap key")
	}
	keys := map[string]stogasTrustKey{}
	for _, key := range trust.Keys {
		if key.Algorithm != "Ed25519" || key.Purpose != "release" || key.PublicKey.Type != "spki" || key.ValidFromSequence <= 0 {
			return nil, fmt.Errorf("invalid Stogas trust key: %s", key.KeyID)
		}
		keys[key.KeyID] = key
	}
	return keys, nil
}

func stogasTrustPayload(trust stogasTrustBundle) ([]byte, error) {
	body := struct {
		Keys   []stogasTrustKey `json:"keys"`
		Schema string           `json:"schema"`
	}{Keys: trust.Keys, Schema: trust.Schema}
	canonical, err := stableJSONValue(body)
	if err != nil {
		return nil, fmt.Errorf("canonicalize Stogas trust bundle: %w", err)
	}
	return append([]byte("stogas trust v1\n"), canonical...), nil
}

func verifySigstoreTrustBundle(bundle sigstoreTrustBundle) (sigstoreTrustedRoot, error) {
	if bundle.Schema != "sigstore.tuf.trust.v1" {
		return sigstoreTrustedRoot{}, fmt.Errorf("unsupported Sigstore trust bundle schema")
	}
	root, err := verifyTUFRootChain(bundle.RootChain)
	if err != nil {
		return sigstoreTrustedRoot{}, err
	}
	timestamp, err := parseTUFMetadata(bundle.Metadata.Timestamp, "timestamp")
	if err != nil {
		return sigstoreTrustedRoot{}, err
	}
	if err := verifyTUFMetadata(timestamp, "timestamp", root); err != nil {
		return sigstoreTrustedRoot{}, err
	}
	if err := assertTUFNotExpired(timestamp, "timestamp"); err != nil {
		return sigstoreTrustedRoot{}, err
	}
	var timestampSigned tufSigned
	if err := json.Unmarshal(timestamp.Signed, &timestampSigned); err != nil {
		return sigstoreTrustedRoot{}, err
	}
	snapshotMeta := timestampSigned.Meta["snapshot.json"]
	if err := verifyTUFMetadataFile(bundle.Metadata.Snapshot, snapshotMeta, "snapshot.json"); err != nil {
		return sigstoreTrustedRoot{}, err
	}
	snapshot, err := parseTUFMetadata(bundle.Metadata.Snapshot, "snapshot")
	if err != nil {
		return sigstoreTrustedRoot{}, err
	}
	if err := verifyTUFMetadata(snapshot, "snapshot", root); err != nil {
		return sigstoreTrustedRoot{}, err
	}
	if err := assertTUFNotExpired(snapshot, "snapshot"); err != nil {
		return sigstoreTrustedRoot{}, err
	}
	var snapshotSigned tufSigned
	if err := json.Unmarshal(snapshot.Signed, &snapshotSigned); err != nil {
		return sigstoreTrustedRoot{}, err
	}
	targetsMeta := snapshotSigned.Meta["targets.json"]
	if err := verifyTUFMetadataFile(bundle.Metadata.Targets, targetsMeta, "targets.json"); err != nil {
		return sigstoreTrustedRoot{}, err
	}
	targets, err := parseTUFMetadata(bundle.Metadata.Targets, "targets")
	if err != nil {
		return sigstoreTrustedRoot{}, err
	}
	if err := verifyTUFMetadata(targets, "targets", root); err != nil {
		return sigstoreTrustedRoot{}, err
	}
	if err := assertTUFNotExpired(targets, "targets"); err != nil {
		return sigstoreTrustedRoot{}, err
	}
	var targetsSigned tufSigned
	if err := json.Unmarshal(targets.Signed, &targetsSigned); err != nil {
		return sigstoreTrustedRoot{}, err
	}
	target, ok := targetsSigned.Targets["trusted_root.json"]
	if !ok {
		return sigstoreTrustedRoot{}, fmt.Errorf("Sigstore TUF targets are missing trusted_root.json")
	}
	trustedRootBytes := []byte(bundle.TrustedRoot)
	if target.Length != 0 && len(trustedRootBytes) != target.Length {
		return sigstoreTrustedRoot{}, fmt.Errorf("Sigstore trusted_root.json length mismatch")
	}
	if expected := target.Hashes["sha256"]; expected != "" && sha256Hex(trustedRootBytes) != expected {
		return sigstoreTrustedRoot{}, fmt.Errorf("Sigstore trusted_root.json SHA-256 mismatch")
	}
	return parseSigstoreTrustedRoot(bundle.TrustedRoot)
}

func verifyTUFRootChain(chain []string) (tufSigned, error) {
	if len(chain) == 0 {
		return tufSigned{}, fmt.Errorf("Sigstore TUF root chain is empty")
	}
	first, err := parseTUFMetadata(chain[0], "root")
	if err != nil {
		return tufSigned{}, err
	}
	firstSigned, err := parseTUFSigned(first)
	if err != nil {
		return tufSigned{}, err
	}
	if firstSigned.Type != "root" || firstSigned.Version != sigstoreTUFBootstrapRootVersion {
		return tufSigned{}, fmt.Errorf("Sigstore TUF bootstrap root version is not pinned")
	}
	firstHash, err := tufSignedSHA256(first)
	if err != nil {
		return tufSigned{}, err
	}
	if firstHash != sigstoreTUFBootstrapRootSignedSHA256 {
		return tufSigned{}, fmt.Errorf("Sigstore TUF bootstrap root does not match pinned root")
	}
	if err := verifyTUFRoleSignatures(first, "root", firstSigned); err != nil {
		return tufSigned{}, err
	}
	trusted := firstSigned
	for _, text := range chain[1:] {
		next, err := parseTUFMetadata(text, "root")
		if err != nil {
			return tufSigned{}, err
		}
		signed, err := parseTUFSigned(next)
		if err != nil {
			return tufSigned{}, err
		}
		if signed.Type != "root" || signed.Version != trusted.Version+1 {
			return tufSigned{}, fmt.Errorf("Sigstore TUF root chain is not sequential")
		}
		if err := verifyTUFRoleSignatures(next, "root", trusted); err != nil {
			return tufSigned{}, err
		}
		if err := verifyTUFRoleSignatures(next, "root", signed); err != nil {
			return tufSigned{}, err
		}
		trusted = signed
	}
	if time.Now().After(parseTUFTime(trusted.Expires)) {
		return tufSigned{}, fmt.Errorf("Sigstore TUF root metadata is expired")
	}
	return trusted, nil
}

func verifyTUFMetadata(metadata tufMetadata, role string, root tufSigned) error {
	signed, err := parseTUFSigned(metadata)
	if err != nil {
		return err
	}
	if signed.Type != role {
		return fmt.Errorf("Sigstore TUF metadata type is not %s", role)
	}
	return verifyTUFRoleSignatures(metadata, role, root)
}

func verifyTUFRoleSignatures(metadata tufMetadata, roleName string, root tufSigned) error {
	role, ok := root.Roles[roleName]
	if !ok || role.Threshold <= 0 || len(role.KeyIDs) < role.Threshold {
		return fmt.Errorf("Sigstore TUF %s role threshold is invalid", roleName)
	}
	canonical, err := canonicalTUFJSONRaw(metadata.Signed)
	if err != nil {
		return fmt.Errorf("canonicalize Sigstore TUF signed body: %w", err)
	}
	keyIDs := map[string]bool{}
	for _, keyID := range role.KeyIDs {
		keyIDs[keyID] = true
	}
	verified := map[string]bool{}
	for _, signature := range metadata.Signatures {
		if !keyIDs[signature.KeyID] || verified[signature.KeyID] {
			continue
		}
		key, ok := root.Keys[signature.KeyID]
		if !ok {
			continue
		}
		sig, err := hex.DecodeString(signature.Signature)
		if err != nil {
			continue
		}
		block, _ := pem.Decode([]byte(key.KeyVal.Public))
		if block == nil {
			continue
		}
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		if verifyPublicKeySignatureWithDetails(publicKey, key.Scheme, canonical, sig) == nil {
			verified[signature.KeyID] = true
		}
	}
	if len(verified) < role.Threshold {
		return fmt.Errorf("Sigstore TUF %s metadata does not meet signature threshold", roleName)
	}
	return nil
}

func verifyTUFMetadataFile(metadata string, expected struct {
	Hashes  map[string]string `json:"hashes"`
	Length  *int              `json:"length"`
	Version int               `json:"version"`
}, name string) error {
	parsed, err := parseTUFMetadata(metadata, name)
	if err != nil {
		return err
	}
	signed, err := parseTUFSigned(parsed)
	if err != nil {
		return err
	}
	if expected.Version != 0 && signed.Version != expected.Version {
		return fmt.Errorf("Sigstore TUF %s version mismatch", name)
	}
	if expected.Length != nil && len([]byte(metadata)) != *expected.Length {
		return fmt.Errorf("Sigstore TUF %s length mismatch", name)
	}
	if expectedHash := expected.Hashes["sha256"]; expectedHash != "" && sha256Hex([]byte(metadata)) != expectedHash {
		return fmt.Errorf("Sigstore TUF %s SHA-256 mismatch", name)
	}
	return nil
}

func parseTUFMetadata(text string, name string) (tufMetadata, error) {
	var metadata tufMetadata
	if err := json.Unmarshal([]byte(text), &metadata); err != nil {
		return metadata, fmt.Errorf("decode Sigstore TUF %s metadata: %w", name, err)
	}
	return metadata, nil
}

func assertTUFNotExpired(metadata tufMetadata, name string) error {
	signed, err := parseTUFSigned(metadata)
	if err != nil {
		return err
	}
	if time.Now().After(parseTUFTime(signed.Expires)) {
		return fmt.Errorf("Sigstore TUF %s metadata is expired", name)
	}
	return nil
}

func parseTUFSigned(metadata tufMetadata) (tufSigned, error) {
	var signed tufSigned
	if len(metadata.Signed) == 0 {
		return signed, fmt.Errorf("Sigstore TUF metadata is missing signed body")
	}
	if err := json.Unmarshal(metadata.Signed, &signed); err != nil {
		return signed, fmt.Errorf("decode Sigstore TUF signed body: %w", err)
	}
	return signed, nil
}

func tufSignedSHA256(metadata tufMetadata) (string, error) {
	canonical, err := canonicalTUFJSONRaw(metadata.Signed)
	if err != nil {
		return "", err
	}
	return sha256Hex(canonical), nil
}

func canonicalTUFJSONRaw(raw json.RawMessage) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return canonicalTUFJSON(value)
}

func canonicalTUFJSON(value any) ([]byte, error) {
	switch typed := value.(type) {
	case nil:
		return []byte("null"), nil
	case bool:
		if typed {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case string:
		return []byte(`"` + strings.ReplaceAll(strings.ReplaceAll(typed, `\`, `\\`), `"`, `\"`) + `"`), nil
	case json.Number:
		text := typed.String()
		if strings.ContainsAny(text, ".eE") {
			return nil, fmt.Errorf("TUF canonical JSON does not allow non-integer numbers")
		}
		return []byte(text), nil
	case []any:
		var out bytes.Buffer
		out.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				out.WriteByte(',')
			}
			child, err := canonicalTUFJSON(item)
			if err != nil {
				return nil, err
			}
			out.Write(child)
		}
		out.WriteByte(']')
		return out.Bytes(), nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		var out bytes.Buffer
		out.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				out.WriteByte(',')
			}
			keyBytes, err := canonicalTUFJSON(key)
			if err != nil {
				return nil, err
			}
			valueBytes, err := canonicalTUFJSON(typed[key])
			if err != nil {
				return nil, err
			}
			out.Write(keyBytes)
			out.WriteByte(':')
			out.Write(valueBytes)
		}
		out.WriteByte('}')
		return out.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported TUF canonical JSON type %T", value)
	}
}

func parseSigstoreTrustedRoot(text string) (sigstoreTrustedRoot, error) {
	var raw struct {
		CertificateAuthorities []struct {
			CertChain struct {
				Certificates []struct {
					RawBytes string `json:"rawBytes"`
				} `json:"certificates"`
			} `json:"certChain"`
			ValidFor validInterval `json:"validFor"`
		} `json:"certificateAuthorities"`
		Tlogs []struct {
			LogID struct {
				KeyID string `json:"keyId"`
			} `json:"logId"`
			PublicKey struct {
				KeyDetails string        `json:"keyDetails"`
				RawBytes   string        `json:"rawBytes"`
				ValidFor   validInterval `json:"validFor"`
			} `json:"publicKey"`
		} `json:"tlogs"`
	}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return sigstoreTrustedRoot{}, fmt.Errorf("decode Sigstore trusted root: %w", err)
	}
	trusted := sigstoreTrustedRoot{RekorKeys: map[string]struct {
		KeyDetails string
		SPKI       string
		ValidFor   validInterval
	}{}}
	for _, authority := range raw.CertificateAuthorities {
		var certs []string
		for _, cert := range authority.CertChain.Certificates {
			if cert.RawBytes != "" {
				certs = append(certs, cert.RawBytes)
			}
		}
		if len(certs) > 0 {
			trusted.FulcioChains = append(trusted.FulcioChains, struct {
				Certs    []string
				ValidFor validInterval
			}{Certs: certs, ValidFor: authority.ValidFor})
		}
	}
	for _, log := range raw.Tlogs {
		if log.LogID.KeyID == "" || log.PublicKey.RawBytes == "" || log.PublicKey.KeyDetails == "" {
			continue
		}
		trusted.RekorKeys[log.LogID.KeyID] = struct {
			KeyDetails string
			SPKI       string
			ValidFor   validInterval
		}{KeyDetails: log.PublicKey.KeyDetails, SPKI: log.PublicKey.RawBytes, ValidFor: log.PublicKey.ValidFor}
	}
	if len(trusted.FulcioChains) == 0 || len(trusted.RekorKeys) == 0 {
		return sigstoreTrustedRoot{}, fmt.Errorf("Sigstore trusted root is missing Fulcio or Rekor material")
	}
	return trusted, nil
}

func verifyGitHubAttestation(attestation githubAttestationBundle, manifest catalogReleaseManifest, catalogSHA256 string, trustedRoot sigstoreTrustedRoot) error {
	cert, integratedTime, err := verifyGitHubRekorEntry(attestation)
	if err != nil {
		return err
	}
	if err := verifyRekorSET(attestation.VerificationMaterial.TlogEntries[0], trustedRoot); err != nil {
		return err
	}
	if err := verifyFulcioCertificate(cert, integratedTime, trustedRoot); err != nil {
		return err
	}
	if err := verifyGitHubCertificatePolicy(cert, manifest); err != nil {
		return err
	}
	if err := verifyGitHubDSSE(attestation, cert); err != nil {
		return err
	}
	if err := assertGitHubAttestationSubject(attestation, catalogSHA256); err != nil {
		return err
	}
	return nil
}

func verifyGitHubRekorEntry(attestation githubAttestationBundle) (*x509.Certificate, time.Time, error) {
	if len(attestation.VerificationMaterial.TlogEntries) == 0 {
		return nil, time.Time{}, fmt.Errorf("catalog GitHub attestation is missing Rekor entry")
	}
	entry := attestation.VerificationMaterial.TlogEntries[0]
	if entry.CanonicalizedBody == "" {
		return nil, time.Time{}, fmt.Errorf("catalog GitHub attestation Rekor entry is missing body")
	}
	body, err := base64.StdEncoding.DecodeString(entry.CanonicalizedBody)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("decode Rekor canonicalized body: %w", err)
	}
	var logged rekorIntotoBody
	if err := json.Unmarshal(body, &logged); err != nil {
		return nil, time.Time{}, fmt.Errorf("decode Rekor canonicalized body: %w", err)
	}
	loggedEnvelope := logged.Spec.Content.Envelope
	if logged.Kind != "intoto" ||
		logged.APIVersion != "0.0.2" ||
		loggedEnvelope.PayloadType != attestation.DSSEEnvelope.PayloadType ||
		loggedEnvelope.Payload != attestation.DSSEEnvelope.Payload ||
		len(loggedEnvelope.Signatures) != 1 ||
		len(attestation.DSSEEnvelope.Signatures) != 1 ||
		loggedEnvelope.Signatures[0].Signature != attestation.DSSEEnvelope.Signatures[0].Signature {
		return nil, time.Time{}, fmt.Errorf("Rekor body does not bind GitHub DSSE envelope")
	}
	certBytes, err := base64.StdEncoding.DecodeString(attestation.VerificationMaterial.Certificate.RawBytes)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("decode Fulcio certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse Fulcio certificate: %w", err)
	}
	return cert, time.Unix(entry.IntegratedTime, 0).UTC(), nil
}

func verifyRekorSET(entry struct {
	CanonicalizedBody string `json:"canonicalizedBody"`
	InclusionPromise  struct {
		SignedEntryTimestamp string `json:"signedEntryTimestamp"`
	} `json:"inclusionPromise"`
	IntegratedTime int64 `json:"integratedTime,string"`
	LogID          struct {
		KeyID string `json:"keyId"`
	} `json:"logId"`
	LogIndex int64 `json:"logIndex,string"`
}, trustedRoot sigstoreTrustedRoot) error {
	key, ok := trustedRoot.RekorKeys[entry.LogID.KeyID]
	if !ok {
		return fmt.Errorf("Rekor log id is not trusted: %s", entry.LogID.KeyID)
	}
	if !validAt(key.ValidFor, time.Unix(entry.IntegratedTime, 0).UTC()) {
		return fmt.Errorf("Rekor key was not valid at integrated time")
	}
	logID, err := base64.StdEncoding.DecodeString(entry.LogID.KeyID)
	if err != nil {
		return fmt.Errorf("decode Rekor log id: %w", err)
	}
	payload, err := stableJSONValue(map[string]any{
		"body":           entry.CanonicalizedBody,
		"integratedTime": entry.IntegratedTime,
		"logID":          hex.EncodeToString(logID),
		"logIndex":       entry.LogIndex,
	})
	if err != nil {
		return fmt.Errorf("canonicalize Rekor SET payload: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(entry.InclusionPromise.SignedEntryTimestamp)
	if err != nil {
		return fmt.Errorf("decode Rekor SET: %w", err)
	}
	return verifySPKISignature(key.SPKI, key.KeyDetails, bytes.TrimSuffix(payload, []byte("\n")), signature)
}

func verifyFulcioCertificate(cert *x509.Certificate, signedAt time.Time, trustedRoot sigstoreTrustedRoot) error {
	if signedAt.Before(cert.NotBefore) || signedAt.After(cert.NotAfter) {
		return fmt.Errorf("Fulcio certificate was not valid at Rekor integrated time")
	}
	for _, chain := range trustedRoot.FulcioChains {
		if !validAt(chain.ValidFor, signedAt) {
			continue
		}
		if verifiesFulcioChain(cert, chain.Certs) {
			return nil
		}
	}
	return fmt.Errorf("Fulcio certificate does not chain to pinned Sigstore roots")
}

func verifiesFulcioChain(leaf *x509.Certificate, chain []string) bool {
	child := leaf
	for _, raw := range chain {
		parentBytes, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return false
		}
		parent, err := x509.ParseCertificate(parentBytes)
		if err != nil {
			return false
		}
		if err := child.CheckSignatureFrom(parent); err != nil {
			return false
		}
		child = parent
	}
	return child.CheckSignatureFrom(child) == nil
}

func verifyGitHubCertificatePolicy(cert *x509.Certificate, manifest catalogReleaseManifest) error {
	if manifest.Git.Repository == "" || !catalogTagPattern.MatchString(manifest.Git.Tag) {
		return fmt.Errorf("catalog release manifest Git policy is invalid")
	}
	if manifest.Git.Ref == "" {
		return fmt.Errorf("catalog release manifest Git ref is missing")
	}
	expectedSAN := fmt.Sprintf("https://github.com/%s/%s@%s", githubAttestationRepository, catalogReleaseWorkflow, manifest.Git.Ref)
	for _, uri := range cert.URIs {
		if uri.String() == expectedSAN {
			if issuer, ok := fulcioIssuer(cert); !ok || issuer != githubOIDCIssuer {
				return fmt.Errorf("Fulcio certificate issuer does not match GitHub Actions OIDC")
			}
			return nil
		}
	}
	return fmt.Errorf("Fulcio certificate SAN does not match catalog release workflow")
}

func fulcioIssuer(cert *x509.Certificate) (string, bool) {
	for _, extension := range cert.Extensions {
		if !extension.Id.Equal(fulcioIssuerOID) {
			continue
		}
		var value string
		if _, err := asn1.Unmarshal(extension.Value, &value); err == nil {
			return value, true
		}
		return strings.Trim(string(extension.Value), "\x00"), true
	}
	return "", false
}

func verifyGitHubDSSE(attestation githubAttestationBundle, cert *x509.Certificate) error {
	envelope := attestation.DSSEEnvelope
	if envelope.PayloadType != "application/vnd.in-toto+json" || len(envelope.Signatures) != 1 {
		return fmt.Errorf("catalog GitHub attestation DSSE envelope is unsupported")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return fmt.Errorf("decode GitHub DSSE payload: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Signature)
	if err != nil {
		return fmt.Errorf("decode GitHub DSSE signature: %w", err)
	}
	if err := verifyPublicKeySignature(cert.PublicKey, dssePAE(envelope.PayloadType, payload), signature); err != nil {
		return fmt.Errorf("GitHub DSSE signature is invalid: %w", err)
	}
	return nil
}

func assertGitHubAttestationSubject(attestation githubAttestationBundle, catalogSHA256 string) error {
	if attestation.DSSEEnvelope.Payload == "" {
		return fmt.Errorf("catalog GitHub attestation is missing DSSE payload")
	}
	payload, err := base64.StdEncoding.DecodeString(attestation.DSSEEnvelope.Payload)
	if err != nil {
		return fmt.Errorf("decode catalog GitHub attestation payload: %w", err)
	}
	var statement inTotoStatement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return fmt.Errorf("decode catalog GitHub attestation statement: %w", err)
	}
	for _, subject := range statement.Subject {
		if subject.Digest["sha256"] == catalogSHA256 {
			return nil
		}
	}
	return fmt.Errorf("catalog GitHub attestation subject does not match catalog hash")
}

func verifySPKISignature(spki string, keyDetails string, data []byte, signature []byte) error {
	der, err := base64.StdEncoding.DecodeString(spki)
	if err != nil {
		return fmt.Errorf("decode pinned public key: %w", err)
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return fmt.Errorf("parse pinned public key: %w", err)
	}
	return verifyPublicKeySignatureWithDetails(key, keyDetails, data, signature)
}

func verifyPublicKeySignature(key any, data []byte, signature []byte) error {
	return verifyPublicKeySignatureWithDetails(key, "", data, signature)
}

func verifyPublicKeySignatureWithDetails(key any, keyDetails string, data []byte, signature []byte) error {
	switch publicKey := key.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(publicKey, data, signature) {
			return fmt.Errorf("ed25519 verification failed")
		}
		return nil
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(data)
		if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
			return fmt.Errorf("ecdsa verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", key)
	}
}

func dssePAE(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len([]byte(payloadType)), payloadType, len(payload))
	return append([]byte(prefix), payload...)
}

func parseTUFTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func validAt(interval validInterval, at time.Time) bool {
	if interval.Start != "" && at.Before(parseTUFTime(interval.Start)) {
		return false
	}
	if interval.End != "" && at.After(parseTUFTime(interval.End)) {
		return false
	}
	return true
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func stableJSON(raw json.RawMessage) ([]byte, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func stableJSONValue(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
