package drand

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/sign/tbls"

	"github.com/maximhq/bifrost/transports/stogas/confidential/reportdata"
)

const (
	QuicknetPublicKeyHex = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
	QuicknetSchemeID     = "bls-unchained-g1-rfc9380"
)

type QuicknetVerifier struct {
	publicKey kyber.Point
	scheme    sign.ThresholdScheme
}

func NewQuicknetVerifier() (*QuicknetVerifier, error) {
	pairing := bls.NewBLS12381SuiteWithDST(
		[]byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"),
		[]byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"),
	)
	publicKeyBytes, err := hex.DecodeString(QuicknetPublicKeyHex)
	if err != nil {
		return nil, err
	}
	publicKey := pairing.G2().Point()
	if err := publicKey.UnmarshalBinary(publicKeyBytes); err != nil {
		return nil, fmt.Errorf("parse drand quicknet public key: %w", err)
	}
	return &QuicknetVerifier{
		publicKey: publicKey,
		scheme:    tbls.NewThresholdSchemeOnG1(pairing),
	}, nil
}

func (v *QuicknetVerifier) Verify(ctx context.Context, beacon reportdata.Drand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v == nil || v.publicKey == nil || v.scheme == nil {
		return fmt.Errorf("drand quicknet verifier is not initialized")
	}
	if err := Validate(beacon); err != nil {
		return err
	}
	signature, err := hex.DecodeString(beacon.Signature)
	if err != nil {
		return fmt.Errorf("decode drand signature: %w", err)
	}
	expectedRandomness, err := RandomnessFromSignature(beacon.Signature)
	if err != nil {
		return err
	}
	if !strings.EqualFold(beacon.Randomness, expectedRandomness) {
		return fmt.Errorf("drand randomness does not match signature")
	}
	if err := v.scheme.VerifyRecovered(v.publicKey.Clone(), quicknetMessage(beacon.Round), signature); err != nil {
		return err
	}
	return nil
}

func quicknetMessage(round uint64) []byte {
	h := sha256.New()
	_ = binary.Write(h, binary.BigEndian, round)
	return h.Sum(nil)
}
