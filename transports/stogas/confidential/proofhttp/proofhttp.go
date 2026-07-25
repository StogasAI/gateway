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
	RequestID             string
	RequestPath           string
	RequestBody           []byte
	CatalogNodeIDs        []string
	ResponseBody          []byte
	E2EETranscriptSHA256 string
	DrandRound            uint64
}

type Output struct {
	Headers map[string]string
	Object  Object
}

type Object struct {
	proof.Payload
	ProofHash        string `json:"proof_hash"`
	Signature        string `json:"signature"`
	SigningPublicKey string `json:"signing_public_key"`
}

func (s *Service) Build(ctx context.Context, input Input) (*Output, error) {
	if s == nil {
		return nil, nil
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	if input.RequestID == "" {
		return nil, errors.New("request id is required")
	}
	if input.RequestPath == "" {
		return nil, errors.New("request path is required")
	}
	if len(input.RequestBody) == 0 {
		return nil, errors.New("request body is required")
	}
	if len(input.ResponseBody) == 0 {
		return nil, errors.New("response body is required")
	}
	if len(input.CatalogNodeIDs) == 0 {
		return nil, errors.New("resolved catalog node ids are required")
	}
	snapshot, err := s.currentValidatedSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	proofInput := proof.Input{
		RequestID:             input.RequestID,
		RequestPath:           input.RequestPath,
		RequestBody:           append([]byte(nil), input.RequestBody...),
		ResponseBody:          append([]byte(nil), input.ResponseBody...),
		CatalogNodeIDs:        append([]string(nil), input.CatalogNodeIDs...),
		DrandRound:            snapshot.Payload.Drand.Round,
		E2EETranscriptSHA256: input.E2EETranscriptSHA256,
	}
	proofHash, err := proof.Hash(proofInput)
	if err != nil {
		return nil, err
	}
	return s.outputForPayload(snapshot, proof.PayloadFor(proofInput), proofHash)
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

func (s *Service) outputForPayload(snapshot *quote.Snapshot, payload proof.Payload, proofHash string) (*Output, error) {
	signature := proof.Sign(s.Signer, proofHash)
	object := Object{
		Payload:          payload,
		ProofHash:        proofHash,
		Signature:        signature,
		SigningPublicKey: snapshot.Payload.Ed25519PublicKey,
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	return &Output{
		Headers: map[string]string{HeaderProof: base64.RawURLEncoding.EncodeToString(encoded)},
		Object: object,
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
	snapshot, err := s.currentValidatedSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	input.DrandRound = snapshot.Payload.Drand.Round
	return newStream(input)
}

func newStream(input Input) (*Stream, error) {
	if input.RequestID == "" || input.RequestPath == "" || len(input.RequestBody) == 0 {
		return nil, errors.New("request proof context is incomplete")
	}
	if len(input.CatalogNodeIDs) == 0 {
		return nil, errors.New("resolved catalog node ids are required")
	}
	if input.DrandRound == 0 {
		return nil, errors.New("drand round is required")
	}
	return &Stream{
		base: input,
		hasher: proof.NewStreamHasher(proof.StreamingInput{
			RequestID:             input.RequestID,
			RequestPath:           input.RequestPath,
			RequestBody:           append([]byte(nil), input.RequestBody...),
			CatalogNodeIDs:        append([]string(nil), input.CatalogNodeIDs...),
			DrandRound:            input.DrandRound,
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

func (svc *Service) FinishStream(ctx context.Context, stream *Stream) (*Output, error) {
	if svc == nil || stream == nil {
		return nil, nil
	}
	snapshot, err := svc.currentValidatedSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := stream.hasher.FinalPayload()
	if err != nil {
		return nil, err
	}
	hash, err := proof.HashPayload(payload)
	if err != nil {
		return nil, err
	}
	return svc.outputForPayload(snapshot, payload, hash)
}
