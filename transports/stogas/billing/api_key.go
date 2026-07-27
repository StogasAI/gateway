package billing

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/google/uuid"
)

const (
	apiKeyPrefix       = "sk_stogas_v1_"
	apiKeyVersion      = uint32(1)
	apiKeyPayloadBytes = 100
	apiKeyMACBytes     = 24
	apiKeyBodyBytes    = apiKeyPayloadBytes + apiKeyMACBytes
)

var errInvalidAPIKeyShape = errors.New("invalid API key")

type APIKeyClaims struct {
	KeyID          string
	FormatVersion  uint32
	OrganizationID string
	ProvisioningID *string
	ResponsibleID  string
	WorkspaceID    string
}

func parseSignedAPIKey(rawKey string, apiKeyPepper string) (*APIKeyClaims, error) {
	if !strings.HasPrefix(rawKey, apiKeyPrefix) {
		return nil, errInvalidAPIKeyShape
	}
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(rawKey, apiKeyPrefix))
	if err != nil || len(body) != apiKeyBodyBytes {
		return nil, errInvalidAPIKeyShape
	}

	payload := body[:apiKeyPayloadBytes]
	actualMAC := body[apiKeyPayloadBytes:]
	hasher := hmac.New(sha256.New, []byte(apiKeyPepper))
	_, _ = hasher.Write(payload)
	expectedMAC := hasher.Sum(nil)[:apiKeyMACBytes]
	if !hmac.Equal(actualMAC, expectedMAC) {
		return nil, errInvalidAPIKeyShape
	}

	formatVersion := binary.BigEndian.Uint32(payload[0:4])
	if formatVersion != apiKeyVersion {
		return nil, errInvalidAPIKeyShape
	}

	keyID, err := uuid.FromBytes(payload[4:20])
	if err != nil || keyID == uuid.Nil {
		return nil, errInvalidAPIKeyShape
	}
	organizationID, err := uuid.FromBytes(payload[20:36])
	if err != nil || organizationID == uuid.Nil {
		return nil, errInvalidAPIKeyShape
	}
	workspaceID, err := uuid.FromBytes(payload[36:52])
	if err != nil || workspaceID == uuid.Nil {
		return nil, errInvalidAPIKeyShape
	}
	responsibleID, err := uuid.FromBytes(payload[52:68])
	if err != nil || responsibleID == uuid.Nil {
		return nil, errInvalidAPIKeyShape
	}

	provisioningID, err := uuid.FromBytes(payload[68:84])
	if err != nil {
		return nil, errInvalidAPIKeyShape
	}
	var provisioningIDString *string
	if provisioningID != uuid.Nil {
		value := provisioningID.String()
		provisioningIDString = &value
	}
	issuanceEntropyIsZero := true
	for _, value := range payload[84:100] {
		if value != 0 {
			issuanceEntropyIsZero = false
			break
		}
	}
	if issuanceEntropyIsZero {
		return nil, errInvalidAPIKeyShape
	}

	return &APIKeyClaims{
		KeyID:          keyID.String(),
		FormatVersion:  formatVersion,
		OrganizationID: organizationID.String(),
		ProvisioningID: provisioningIDString,
		ResponsibleID:  responsibleID.String(),
		WorkspaceID:    workspaceID.String(),
	}, nil
}

func hashAPIKey(token string, apiKeyPepper string) string {
	hasher := hmac.New(sha512.New, []byte(apiKeyPepper))
	_, _ = hasher.Write([]byte(token))
	return hex.EncodeToString(hasher.Sum(nil))
}
