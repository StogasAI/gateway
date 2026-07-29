package proofhttp

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/confidential/quote"
	"github.com/maximhq/bifrost/transports/stogas/confidential/reportdata"
)

const (
	HeaderProof  = "X-Stogas-Proof"
	SSEEventName = "stogas.proof"
)

type SnapshotProvider interface {
	Current(ctx context.Context) (*quote.Snapshot, error)
}

type Service struct {
	Quotes SnapshotProvider
	Signer ed25519.PrivateKey
}

type Input struct {
	RequestBody          []byte
	CatalogDigest        string
	CatalogNodeIDs       []string
	ResponseBody         []byte
	E2EETranscriptSHA256 string
}

type Output struct {
	Headers map[string]string
	Object  Object
}

type Object struct {
	proof.Payload
	Signature string `json:"signature"`
}

func (s *Service) Build(ctx context.Context, input Input) (*Output, error) {
	if s == nil {
		return nil, nil
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	if len(input.RequestBody) == 0 {
		return nil, errors.New("request body is required")
	}
	if len(input.ResponseBody) == 0 {
		return nil, errors.New("response body is required")
	}
	if input.CatalogDigest == "" {
		return nil, errors.New("catalog digest is required")
	}
	if len(input.CatalogNodeIDs) != 5 {
		return nil, errors.New("all five resolved catalog nodes are required")
	}
	_, err := s.currentValidatedSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	proofInput := proof.Input{
		RequestBody:          append([]byte(nil), input.RequestBody...),
		ResponseBody:         append([]byte(nil), input.ResponseBody...),
		CatalogDigest:        input.CatalogDigest,
		CatalogNodeIDs:       append([]string(nil), input.CatalogNodeIDs...),
		E2EETranscriptSHA256: input.E2EETranscriptSHA256,
	}
	return s.outputForPayload(proof.PayloadFor(proofInput))
}

func (s *Service) currentValidatedSnapshot(ctx context.Context) (*quote.Snapshot, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	snapshot, err := s.Quotes.Current(ctx)
	if err != nil {
		return nil, err
	}
	if snapshot == nil || len(snapshot.Quote) == 0 {
		return nil, errors.New("current quote snapshot is empty")
	}
	reportDataHex, err := reportdata.HashHex(snapshot.Payload)
	if err != nil {
		return nil, err
	}
	if snapshot.ReportDataHex == "" || snapshot.ReportDataHex != reportDataHex {
		return nil, errors.New("current quote snapshot report-data hash mismatch")
	}
	publicKey, ok := s.Signer.Public().(ed25519.PublicKey)
	if !ok || snapshot.Payload.Ed25519PublicKey != base64.RawURLEncoding.EncodeToString(publicKey) {
		return nil, errors.New("confidential proof signer does not match report-data ed25519 key")
	}
	return snapshot, nil
}

func (s *Service) outputForPayload(payload proof.Payload) (*Output, error) {
	signature, err := proof.Sign(s.Signer, payload)
	if err != nil {
		return nil, err
	}
	object := Object{
		Payload:   payload,
		Signature: signature,
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	return &Output{
		Headers: map[string]string{HeaderProof: base64.RawURLEncoding.EncodeToString(encoded)},
		Object:  object,
	}, nil
}

func (s *Service) validate() error {
	if s == nil {
		return nil
	}
	if s.Quotes == nil {
		return errors.New("confidential proof quote provider is required")
	}
	if len(s.Signer) != ed25519.PrivateKeySize {
		return errors.New("confidential proof signer is required")
	}
	return nil
}

type Stream struct {
	base   Input
	hasher *proof.StreamHasher
}

func (s *Service) NewStream(ctx context.Context, input Input) (*Stream, error) {
	if s == nil {
		return nil, nil
	}
	if _, err := s.currentValidatedSnapshot(ctx); err != nil {
		return nil, err
	}
	return newStream(input)
}

func newStream(input Input) (*Stream, error) {
	if len(input.RequestBody) == 0 {
		return nil, errors.New("request proof context is incomplete")
	}
	if input.CatalogDigest == "" {
		return nil, errors.New("catalog digest is required")
	}
	if len(input.CatalogNodeIDs) != 5 {
		return nil, errors.New("all five resolved catalog nodes are required")
	}
	return &Stream{
		base: input,
		hasher: proof.NewStreamHasher(proof.StreamingInput{
			RequestBody:          append([]byte(nil), input.RequestBody...),
			CatalogDigest:        input.CatalogDigest,
			CatalogNodeIDs:       append([]string(nil), input.CatalogNodeIDs...),
			E2EETranscriptSHA256: input.E2EETranscriptSHA256,
		}),
	}, nil
}

func (s *Stream) WriteSentChunk(chunk []byte) {
	if s == nil || s.hasher == nil || len(chunk) == 0 {
		return
	}
	s.hasher.WriteChunk(chunk)
}

func (s *Stream) SetCatalogNodeIDs(nodeIDs []string) {
	if s == nil || s.hasher == nil {
		return
	}
	s.hasher.SetCatalogNodeIDs(nodeIDs)
}

func (svc *Service) FinishStream(ctx context.Context, stream *Stream) (*Output, error) {
	if svc == nil || stream == nil {
		return nil, nil
	}
	if _, err := svc.currentValidatedSnapshot(ctx); err != nil {
		return nil, err
	}
	return svc.outputForPayload(stream.hasher.FinalPayload())
}
