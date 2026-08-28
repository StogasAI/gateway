package e2ee

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

const (
	Version                  = 1
	ContentType              = "application/vnd.stogas.e2ee"
	ContentEncryptionKeySize = 32
	KeyIDSize                = sha256.Size
	MaxEnvelopeSize          = 128 * 1024 * 1024
	MaxAcceptanceWindow      = 2 * time.Minute
	ClockSkewAllowance       = 30 * time.Second
	MaxAPIKeySize            = 4 * 1024
	MaxCiphertextSize        = 94 * 1024 * 1024
	MaxResponseBodySize      = 65 * 1024 * 1024
	MaxResponseWireSize      = 66 * 1024 * 1024
	RecipientPublicKeySize   = 1_216
	EncapsulatedKeySize      = 1_120

	maxResponseRecordSize = 64 * 1024
	maxResponseMetadata   = 64 * 1024
	responseNonceSize     = 12
	maxV1Recipients       = 1<<16 - 1
)

var (
	ErrInvalidEnvelope   = errors.New("invalid Stogas E2EE envelope")
	ErrRecipientNotFound = errors.New("E2EE request does not include this node")

	responseMagic = []byte{'S', 'T', 'G', 'E', Version}
)

type Recipient struct {
	KeyID           string `json:"key_id"`
	EncapsulatedKey string `json:"encapsulated_key"`
	WrappedKey      string `json:"wrapped_key"`
}

type Envelope struct {
	Version      int         `json:"version"`
	RequestID    string      `json:"request_id"`
	BundleSHA256 string      `json:"bundle_sha256"`
	ExpiresAtMS  int64       `json:"expires_at_ms"`
	Recipients   []Recipient `json:"recipients"`
	Ciphertext   string      `json:"ciphertext"`
}

type InnerRequest struct {
	APIKey              string               `json:"api_key"`
	Accept              string               `json:"accept,omitempty"`
	Receipt             string               `json:"receipt,omitempty"`
	UpstreamCredentials *UpstreamCredentials `json:"upstream_credentials,omitempty"`
	Body                json.RawMessage      `json:"body"`
}

type UpstreamCredentials struct {
	Anthropic string `json:"anthropic,omitempty"`
	Chutes    string `json:"chutes,omitempty"`
	OpenAI    string `json:"openai,omitempty"`
}

type PublicRecipient struct {
	PublicKey []byte
}

type Session struct {
	RequestID       string
	transcriptHash  [sha256.Size]byte
	responseAEAD    cipher.AEAD
	responseStarted atomic.Bool
}

// TranscriptSHA256 is the channel binding for the exact E2EE request. It
// commits to the protocol version, method, path, request ID, bundle hash,
// acceptance deadline, and complete ordered recipient key-ID set.
func (s *Session) TranscriptSHA256() string {
	if s == nil {
		return ""
	}
	return hex.EncodeToString(s.transcriptHash[:])
}

type ResponseMetadata struct {
	StatusCode  int               `json:"status"`
	ContentType string            `json:"content_type"`
	Headers     map[string]string `json:"headers,omitempty"`
}

type DecodedResponse struct {
	Metadata ResponseMetadata
	Body     []byte
}

func KeyID(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func SealRequestWithID(method, path, requestID string, expiresAt time.Time, bundleSHA256 string, recipients []PublicRecipient, inner InnerRequest) ([]byte, *Session, error) {
	if err := validateRecipientCount(len(recipients)); err != nil {
		return nil, nil, err
	}
	if err := validateInnerRequest(inner); err != nil {
		return nil, nil, err
	}
	if _, err := parseCanonicalUUID(requestID); err != nil {
		return nil, nil, err
	}
	bundleHash, err := decodeBundleHash(bundleSHA256)
	if err != nil {
		return nil, nil, err
	}

	type recipientKey struct {
		id  [KeyIDSize]byte
		key hpke.PublicKey
	}
	keys := make([]recipientKey, 0, len(recipients))
	kem := hpke.MLKEM768X25519()
	for _, recipient := range recipients {
		if len(recipient.PublicKey) != RecipientPublicKeySize {
			return nil, nil, fmt.Errorf("%w: recipient X-Wing public key must be %d bytes", ErrInvalidEnvelope, RecipientPublicKeySize)
		}
		key, err := kem.NewPublicKey(recipient.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: invalid recipient public key", ErrInvalidEnvelope)
		}
		keys = append(keys, recipientKey{id: sha256.Sum256(recipient.PublicKey), key: key})
	}
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i].id[:], keys[j].id[:]) < 0
	})
	for i := 1; i < len(keys); i++ {
		if keys[i].id == keys[i-1].id {
			return nil, nil, fmt.Errorf("%w: duplicate recipient", ErrInvalidEnvelope)
		}
	}
	keyIDs := make([][KeyIDSize]byte, len(keys))
	for i := range keys {
		keyIDs[i] = keys[i].id
	}
	transcript, err := buildTranscript(method, path, requestID, bundleHash, expiresAt.UnixMilli(), keyIDs)
	if err != nil {
		return nil, nil, err
	}
	transcriptHash := sha256.Sum256(transcript)

	contentKey := make([]byte, ContentEncryptionKeySize)
	if _, err := io.ReadFull(rand.Reader, contentKey); err != nil {
		return nil, nil, fmt.Errorf("generate content key: %w", err)
	}
	defer clear(contentKey)
	innerJSON, err := json.Marshal(inner)
	if err != nil {
		return nil, nil, fmt.Errorf("encode inner request: %w", err)
	}
	defer clear(innerJSON)
	requestAEAD, requestNonce, responseAEAD, err := deriveAEADs(contentKey, transcriptHash)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := requestAEAD.Seal(nil, requestNonce[:], innerJSON, transcript)

	envelope := Envelope{
		Version:      Version,
		RequestID:    requestID,
		BundleSHA256: strings.ToLower(bundleSHA256),
		ExpiresAtMS:  expiresAt.UnixMilli(),
		Recipients:   make([]Recipient, 0, len(keys)),
		Ciphertext:   base64.RawURLEncoding.EncodeToString(ciphertext),
	}
	info := hpkeInfo(transcriptHash)
	for _, key := range keys {
		encapsulated, sender, err := hpke.NewSender(key.key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
		if err != nil {
			return nil, nil, fmt.Errorf("initialize recipient HPKE: %w", err)
		}
		wrapped, err := sender.Seal(transcript, contentKey)
		if err != nil {
			return nil, nil, fmt.Errorf("wrap content key: %w", err)
		}
		envelope.Recipients = append(envelope.Recipients, Recipient{
			KeyID:           base64.RawURLEncoding.EncodeToString(key.id[:]),
			EncapsulatedKey: base64.RawURLEncoding.EncodeToString(encapsulated),
			WrappedKey:      base64.RawURLEncoding.EncodeToString(wrapped),
		})
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, nil, fmt.Errorf("encode E2EE envelope: %w", err)
	}
	if err := validateEnvelopeSize(len(encoded)); err != nil {
		return nil, nil, err
	}
	return encoded, newSession(requestID, transcriptHash, responseAEAD), nil
}

func OpenRequest(body []byte, method, path string, privateKey hpke.PrivateKey, now time.Time) (*InnerRequest, *Session, error) {
	if err := validateEnvelopeSize(len(body)); err != nil {
		return nil, nil, err
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if privateKey == nil || privateKey.KEM().ID() != hpke.MLKEM768X25519().ID() {
		return nil, nil, fmt.Errorf("%w: X-Wing node key is unavailable", ErrInvalidEnvelope)
	}

	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if envelope.Version != Version {
		return nil, nil, fmt.Errorf("%w: unsupported version", ErrInvalidEnvelope)
	}
	if _, err := parseCanonicalUUID(envelope.RequestID); err != nil {
		return nil, nil, err
	}
	bundleHash, err := decodeBundleHash(envelope.BundleSHA256)
	if err != nil {
		return nil, nil, err
	}
	expiresAt := time.UnixMilli(envelope.ExpiresAtMS).UTC()
	now = now.UTC()
	if expiresAt.Before(now.Add(-ClockSkewAllowance)) {
		return nil, nil, fmt.Errorf("%w: request acceptance deadline has passed", ErrInvalidEnvelope)
	}
	if expiresAt.After(now.Add(MaxAcceptanceWindow + ClockSkewAllowance)) {
		return nil, nil, fmt.Errorf("%w: request acceptance deadline is too far in the future", ErrInvalidEnvelope)
	}
	if err := validateRecipientCount(len(envelope.Recipients)); err != nil {
		return nil, nil, err
	}

	keyIDs := make([][KeyIDSize]byte, len(envelope.Recipients))
	localKeyID := sha256.Sum256(privateKey.PublicKey().Bytes())
	localIndex := -1
	for i, recipient := range envelope.Recipients {
		keyID, err := decodeFixedBase64(recipient.KeyID, KeyIDSize)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: invalid recipient key_id", ErrInvalidEnvelope)
		}
		copy(keyIDs[i][:], keyID)
		if i > 0 && bytes.Compare(keyIDs[i-1][:], keyIDs[i][:]) >= 0 {
			return nil, nil, fmt.Errorf("%w: recipients must be unique and sorted by key_id", ErrInvalidEnvelope)
		}
		if keyIDs[i] == localKeyID {
			localIndex = i
		}
	}
	if localIndex < 0 {
		return nil, nil, ErrRecipientNotFound
	}
	transcript, err := buildTranscript(method, path, envelope.RequestID, bundleHash, envelope.ExpiresAtMS, keyIDs)
	if err != nil {
		return nil, nil, err
	}
	transcriptHash := sha256.Sum256(transcript)

	local := envelope.Recipients[localIndex]
	encapsulated, err := base64.RawURLEncoding.DecodeString(local.EncapsulatedKey)
	if err != nil || len(encapsulated) != EncapsulatedKeySize || base64.RawURLEncoding.EncodeToString(encapsulated) != local.EncapsulatedKey {
		return nil, nil, fmt.Errorf("%w: invalid encapsulated key", ErrInvalidEnvelope)
	}
	wrapped, err := base64.RawURLEncoding.DecodeString(local.WrappedKey)
	if err != nil || len(wrapped) != ContentEncryptionKeySize+16 || base64.RawURLEncoding.EncodeToString(wrapped) != local.WrappedKey {
		return nil, nil, fmt.Errorf("%w: invalid wrapped key", ErrInvalidEnvelope)
	}
	recipient, err := hpke.NewRecipient(encapsulated, privateKey, hpke.HKDFSHA256(), hpke.AES256GCM(), hpkeInfo(transcriptHash))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: HPKE setup failed", ErrInvalidEnvelope)
	}
	contentKey, err := recipient.Open(transcript, wrapped)
	if err != nil || len(contentKey) != ContentEncryptionKeySize {
		return nil, nil, fmt.Errorf("%w: content key authentication failed", ErrInvalidEnvelope)
	}
	defer clear(contentKey)
	requestAEAD, requestNonce, responseAEAD, err := deriveAEADs(contentKey, transcriptHash)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil ||
		len(ciphertext) < requestAEAD.Overhead() ||
		len(ciphertext) > MaxCiphertextSize ||
		base64.RawURLEncoding.EncodeToString(ciphertext) != envelope.Ciphertext {
		return nil, nil, fmt.Errorf("%w: invalid ciphertext", ErrInvalidEnvelope)
	}
	plaintext, err := requestAEAD.Open(nil, requestNonce[:], ciphertext, transcript)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: request authentication failed", ErrInvalidEnvelope)
	}
	defer clear(plaintext)
	if err := rejectDuplicateJSONKeys(plaintext); err != nil {
		return nil, nil, fmt.Errorf("%w: invalid inner request: %v", ErrInvalidEnvelope, err)
	}
	var inner InnerRequest
	innerDecoder := json.NewDecoder(bytes.NewReader(plaintext))
	innerDecoder.DisallowUnknownFields()
	if err := innerDecoder.Decode(&inner); err != nil {
		return nil, nil, fmt.Errorf("%w: invalid inner request", ErrInvalidEnvelope)
	}
	if err := ensureJSONEOF(innerDecoder); err != nil {
		return nil, nil, fmt.Errorf("%w: invalid inner request", ErrInvalidEnvelope)
	}
	if err := validateInnerRequest(inner); err != nil {
		return nil, nil, err
	}
	return &inner, newSession(envelope.RequestID, transcriptHash, responseAEAD), nil
}

func validateInnerRequest(inner InnerRequest) error {
	if !validCredential(inner.APIKey) {
		return fmt.Errorf("%w: inner api_key is required", ErrInvalidEnvelope)
	}
	if len(inner.Accept) > 256 {
		return fmt.Errorf("%w: inner request metadata is too large", ErrInvalidEnvelope)
	}
	if inner.Accept != "" && !validHTTPFieldValue(inner.Accept, false) {
		return fmt.Errorf("%w: inner request metadata contains invalid characters", ErrInvalidEnvelope)
	}
	if inner.Receipt != "" && inner.Receipt != "v1" {
		return fmt.Errorf("%w: inner receipt must be v1", ErrInvalidEnvelope)
	}
	if inner.UpstreamCredentials != nil {
		credentials := inner.UpstreamCredentials
		if credentials.Anthropic == "" && credentials.Chutes == "" && credentials.OpenAI == "" {
			return fmt.Errorf("%w: upstream_credentials must not be empty", ErrInvalidEnvelope)
		}
		for _, credential := range []string{credentials.Anthropic, credentials.Chutes, credentials.OpenAI} {
			if credential != "" && !validCredential(credential) {
				return fmt.Errorf("%w: upstream credential is invalid", ErrInvalidEnvelope)
			}
		}
	}
	if len(inner.Body) == 0 || !json.Valid(inner.Body) {
		return fmt.Errorf("%w: inner body must be valid JSON", ErrInvalidEnvelope)
	}
	return nil
}

func validCredential(value string) bool {
	if len(value) == 0 || len(value) > MaxAPIKeySize {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validHTTPFieldValue(value string, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}
	if strings.TrimSpace(value) != value {
		return false
	}
	for index := range len(value) {
		if value[index] != '\t' && (value[index] < 0x20 || value[index] > 0x7e) {
			return false
		}
	}
	return true
}

func validHTTPFieldName(value string) bool {
	if value == "" {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func validContentType(value string) bool {
	if len(value) == 0 || len(value) > 256 || !validHTTPFieldValue(value, false) {
		return false
	}
	mediaType, _, _ := strings.Cut(value, ";")
	major, minor, ok := strings.Cut(mediaType, "/")
	return ok && major != "" && minor != "" && !strings.Contains(minor, "/") &&
		validHTTPFieldName(major) && validHTTPFieldName(minor)
}

func decodeBundleHash(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || value != strings.ToLower(value) {
		return result, fmt.Errorf("%w: bundle_sha256 must be 64 lowercase hexadecimal characters", ErrInvalidEnvelope)
	}
	copy(result[:], decoded)
	return result, nil
}

func decodeFixedBase64(value string, size int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidEnvelope
	}
	return decoded, nil
}

func buildTranscript(method, path, requestID string, bundleHash [sha256.Size]byte, expiresAtMS int64, keyIDs [][KeyIDSize]byte) ([]byte, error) {
	if err := validateRecipientCount(len(keyIDs)); err != nil {
		return nil, err
	}
	id, err := parseCanonicalUUID(requestID)
	if err != nil {
		return nil, err
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method != "POST" {
		return nil, fmt.Errorf("%w: E2EE requests require POST", ErrInvalidEnvelope)
	}
	if path != "/v1/chat/completions" && path != "/v1/responses" {
		return nil, fmt.Errorf("%w: unsupported inference path", ErrInvalidEnvelope)
	}
	var out bytes.Buffer
	out.WriteString("stogas.e2ee.request.v1")
	out.WriteByte(0)
	writeLengthPrefixed(&out, []byte(method))
	writeLengthPrefixed(&out, []byte(path))
	out.Write(id[:])
	out.Write(bundleHash[:])
	_ = binary.Write(&out, binary.BigEndian, expiresAtMS)
	_ = binary.Write(&out, binary.BigEndian, uint16(len(keyIDs)))
	for _, keyID := range keyIDs {
		out.Write(keyID[:])
	}
	return out.Bytes(), nil
}

func validateRecipientCount(count int) error {
	if count == 0 {
		return fmt.Errorf("%w: at least one recipient is required", ErrInvalidEnvelope)
	}
	if count > maxV1Recipients {
		return fmt.Errorf("%w: recipient count exceeds the E2EE v1 wire limit of %d", ErrInvalidEnvelope, maxV1Recipients)
	}
	return nil
}

func validateEnvelopeSize(size int) error {
	if size > MaxEnvelopeSize {
		return fmt.Errorf("%w: encoded envelope exceeds the protocol limit", ErrInvalidEnvelope)
	}
	return nil
}

func parseCanonicalUUID(value string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil || id.String() != value {
		return uuid.Nil, fmt.Errorf("%w: request_id must be a lowercase canonical UUID", ErrInvalidEnvelope)
	}
	return id, nil
}

func writeLengthPrefixed(out *bytes.Buffer, value []byte) {
	_ = binary.Write(out, binary.BigEndian, uint16(len(value)))
	out.Write(value)
}

func hpkeInfo(transcriptHash [sha256.Size]byte) []byte {
	return append([]byte("stogas.e2ee.content-key.v1\x00"), transcriptHash[:]...)
}

func deriveAEADs(contentKey []byte, transcriptHash [sha256.Size]byte) (cipher.AEAD, [12]byte, cipher.AEAD, error) {
	var requestNonce [12]byte
	if len(contentKey) != ContentEncryptionKeySize {
		return nil, requestNonce, nil, fmt.Errorf("%w: invalid content key length", ErrInvalidEnvelope)
	}
	prk := hkdf.Extract(sha256.New, contentKey, transcriptHash[:])
	defer clear(prk)
	requestKey, err := expand(prk, "stogas.e2ee.request.key.v1", 32)
	if err != nil {
		return nil, requestNonce, nil, err
	}
	defer clear(requestKey)
	requestNonceBytes, err := expand(prk, "stogas.e2ee.request.nonce.v1", len(requestNonce))
	if err != nil {
		return nil, requestNonce, nil, err
	}
	defer clear(requestNonceBytes)
	responseKey, err := expand(prk, "stogas.e2ee.response.key.v1", 32)
	if err != nil {
		return nil, requestNonce, nil, err
	}
	defer clear(responseKey)
	copy(requestNonce[:], requestNonceBytes)
	requestAEAD, err := newAESGCM(requestKey)
	if err != nil {
		return nil, requestNonce, nil, err
	}
	responseAEAD, err := newAESGCM(responseKey)
	if err != nil {
		return nil, requestNonce, nil, err
	}
	return requestAEAD, requestNonce, responseAEAD, nil
}

func expand(prk []byte, label string, size int) ([]byte, error) {
	result := make([]byte, size)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte(label)), result); err != nil {
		return nil, fmt.Errorf("derive E2EE key material: %w", err)
	}
	return result, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize AES-256: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize AES-256-GCM: %w", err)
	}
	return aead, nil
}

func newSession(requestID string, transcriptHash [sha256.Size]byte, responseAEAD cipher.AEAD) *Session {
	return &Session{
		RequestID:      requestID,
		transcriptHash: transcriptHash,
		responseAEAD:   responseAEAD,
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}
