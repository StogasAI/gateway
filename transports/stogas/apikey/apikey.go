package apikey

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
	TokenPepperInfo = "stogas:token:pepper"

	Prefix       = "sk_stogas_v1_"
	Version      = uint32(1)
	PayloadBytes = 85
	MACBytes     = 24
	BodyBytes    = PayloadBytes + MACBytes

	TypePersonal    = byte(1)
	TypeExternal    = byte(2)
	TypeProvisioned = byte(3)
)

var ErrInvalid = errors.New("invalid API key")

type Claims struct {
	KeyID          string
	KeyType        byte
	KeyVersion     uint32
	OrganizationID string
	ProvisioningID *string
	ResponsibleID  string
	WorkspaceID    string
}

func DeriveTokenPepper(authSecret string) (string, error) {
	reader := hkdf.New(sha256.New, []byte(authSecret), nil, []byte(TokenPepperInfo))
	derived := make([]byte, 32)
	if _, err := io.ReadFull(reader, derived); err != nil {
		return "", fmt.Errorf("derive token pepper: %w", err)
	}
	return hex.EncodeToString(derived), nil
}

func Validate(rawKey string, tokenPepper string) error {
	if _, err := ParseSigned(rawKey, tokenPepper); err != nil {
		return ErrInvalid
	}
	return nil
}

func ParseSigned(rawKey string, tokenPepper string) (*Claims, error) {
	if !strings.HasPrefix(rawKey, Prefix) {
		return nil, ErrInvalid
	}
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(rawKey, Prefix))
	if err != nil || len(body) != BodyBytes {
		return nil, ErrInvalid
	}

	payload := body[:PayloadBytes]
	actualMAC := body[PayloadBytes:]
	hasher := hmac.New(sha256.New, []byte(tokenPepper))
	_, _ = hasher.Write(payload)
	expectedMAC := hasher.Sum(nil)[:MACBytes]
	if !hmac.Equal(actualMAC, expectedMAC) {
		return nil, ErrInvalid
	}

	keyVersion := binary.BigEndian.Uint32(payload[0:4])
	if keyVersion != Version {
		return nil, ErrInvalid
	}

	keyID, err := uuid.FromBytes(payload[4:20])
	if err != nil || keyID == uuid.Nil {
		return nil, ErrInvalid
	}
	organizationID, err := uuid.FromBytes(payload[20:36])
	if err != nil || organizationID == uuid.Nil {
		return nil, ErrInvalid
	}
	workspaceID, err := uuid.FromBytes(payload[36:52])
	if err != nil || workspaceID == uuid.Nil {
		return nil, ErrInvalid
	}
	responsibleID, err := uuid.FromBytes(payload[52:68])
	if err != nil || responsibleID == uuid.Nil {
		return nil, ErrInvalid
	}

	keyType := payload[68]
	provisioningID, err := uuid.FromBytes(payload[69:85])
	if err != nil {
		return nil, ErrInvalid
	}
	var provisioningIDString *string
	switch keyType {
	case TypePersonal, TypeExternal:
		if provisioningID != uuid.Nil {
			return nil, ErrInvalid
		}
	case TypeProvisioned:
		if provisioningID == uuid.Nil {
			return nil, ErrInvalid
		}
		value := provisioningID.String()
		provisioningIDString = &value
	default:
		return nil, ErrInvalid
	}

	return &Claims{
		KeyID:          keyID.String(),
		KeyType:        keyType,
		KeyVersion:     keyVersion,
		OrganizationID: organizationID.String(),
		ProvisioningID: provisioningIDString,
		ResponsibleID:  responsibleID.String(),
		WorkspaceID:    workspaceID.String(),
	}, nil
}

func Hash(token string, tokenPepper string) string {
	hasher := hmac.New(sha512.New, []byte(tokenPepper))
	_, _ = hasher.Write([]byte(token))
	return hex.EncodeToString(hasher.Sum(nil))
}
