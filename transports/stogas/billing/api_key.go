package billing

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

const (
	apiKeyPepperInfo = "stogas:token:pepper"

	apiKeyPrefix       = "sk_stogas_v1_"
	apiKeyVersion      = uint32(1)
	apiKeyPayloadBytes = 85
	apiKeyMACBytes     = 24
	apiKeyBodyBytes    = apiKeyPayloadBytes + apiKeyMACBytes

	apiKeyTypePersonal    = byte(1)
	apiKeyTypeExternal    = byte(2)
	apiKeyTypeProvisioned = byte(3)
)

var errInvalidAPIKeyShape = errors.New("invalid API key")

type APIKeyClaims struct {
	KeyID          string
	KeyType        byte
	KeyVersion     uint32
	OrganizationID string
	ProvisioningID *string
	ResponsibleID  string
	WorkspaceID    string
}

func deriveTokenPepper(authSecret string) (string, error) {
	reader := hkdf.New(sha256.New, []byte(authSecret), nil, []byte(apiKeyPepperInfo))
	derived := make([]byte, 32)
	if _, err := io.ReadFull(reader, derived); err != nil {
		return "", fmt.Errorf("derive token pepper: %w", err)
	}
	return hex.EncodeToString(derived), nil
}

func parseSignedAPIKey(rawKey string, tokenPepper string) (*APIKeyClaims, error) {
	if !strings.HasPrefix(rawKey, apiKeyPrefix) {
		return nil, errInvalidAPIKeyShape
	}
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(rawKey, apiKeyPrefix))
	if err != nil || len(body) != apiKeyBodyBytes {
		return nil, errInvalidAPIKeyShape
	}

	payload := body[:apiKeyPayloadBytes]
	actualMAC := body[apiKeyPayloadBytes:]
	hasher := hmac.New(sha256.New, []byte(tokenPepper))
	_, _ = hasher.Write(payload)
	expectedMAC := hasher.Sum(nil)[:apiKeyMACBytes]
	if !hmac.Equal(actualMAC, expectedMAC) {
		return nil, errInvalidAPIKeyShape
	}

	keyVersion := binary.BigEndian.Uint32(payload[0:4])
	if keyVersion != apiKeyVersion {
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

	keyType := payload[68]
	provisioningID, err := uuid.FromBytes(payload[69:85])
	if err != nil {
		return nil, errInvalidAPIKeyShape
	}
	var provisioningIDString *string
	switch keyType {
	case apiKeyTypePersonal, apiKeyTypeExternal:
		if provisioningID != uuid.Nil {
			return nil, errInvalidAPIKeyShape
		}
	case apiKeyTypeProvisioned:
		if provisioningID == uuid.Nil {
			return nil, errInvalidAPIKeyShape
		}
		value := provisioningID.String()
		provisioningIDString = &value
	default:
		return nil, errInvalidAPIKeyShape
	}

	return &APIKeyClaims{
		KeyID:          keyID.String(),
		KeyType:        keyType,
		KeyVersion:     keyVersion,
		OrganizationID: organizationID.String(),
		ProvisioningID: provisioningIDString,
		ResponsibleID:  responsibleID.String(),
		WorkspaceID:    workspaceID.String(),
	}, nil
}

func hashAPIKey(token string, tokenPepper string) string {
	hasher := hmac.New(sha512.New, []byte(tokenPepper))
	_, _ = hasher.Write([]byte(token))
	return hex.EncodeToString(hasher.Sum(nil))
}
