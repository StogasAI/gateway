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
	HeaderProof      = "X-Stogas-Proof"
	SSECommentPrefix = "stogas "
)

type SnapshotProvider interface {
	Current(ctx context.Context) (*quote.Snapshot, error)
}

type snapshotRefresher interface {
	Refresh(ctx context.Context) error
}

type Service struct {
	Quotes SnapshotProvider
	Signer ed25519.PrivateKey
}

type Input = proof.Input

type Output struct {
	Headers map[string]string
	Object  proof.Object
}

// ValidateCatalog requires the active request catalog to match the current quote snapshot.
// A refresh-capable provider gets one synchronous refresh before the request fails closed.
func (s *Service) ValidateCatalog(ctx context.Context, catalogDigest string, catalogSequence uint64) error {
	if s == nil {
		return nil
	}
	if catalogDigest == "" {
		return errors.New("catalog identity is required")
	}
	snapshot, err := s.currentValidatedSnapshot(ctx)
	if err != nil {
		return err
	}
	if snapshot.Payload.Catalog.Digest == catalogDigest && snapshot.Payload.Catalog.Sequence == catalogSequence {
		return nil
	}
	refresher, ok := s.Quotes.(snapshotRefresher)
	if !ok {
		return errors.New("active catalog does not match the current quote snapshot")
	}
	if err := refresher.Refresh(ctx); err != nil {
		return err
	}
	snapshot, err = s.currentValidatedSnapshot(ctx)
	if err != nil {
		return err
	}
	if snapshot.Payload.Catalog.Digest != catalogDigest || snapshot.Payload.Catalog.Sequence != catalogSequence {
		return errors.New("active catalog does not match the current quote snapshot")
	}
	return nil
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
	if !proof.ValidMetadata(input.Metadata) {
		return nil, errors.New("response proof metadata is invalid")
	}
	if err := s.ValidateCatalog(ctx, input.Metadata.Catalog.Digest, input.Metadata.Catalog.Sequence); err != nil {
		return nil, err
	}
	proofInput := input
	proofInput.RequestBody = append([]byte(nil), input.RequestBody...)
	proofInput.ResponseBody = append([]byte(nil), input.ResponseBody...)
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
	object := proof.ObjectFor(payload, signature)
	encoded, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	if len(encoded) > proof.MaxObjectBytes {
		return nil, errors.New("response proof exceeds its encoded size limit")
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
	hasher *proof.StreamHasher
}

func (s *Service) NewStream(ctx context.Context, input Input) (*Stream, error) {
	if s == nil {
		return nil, nil
	}
	if err := s.ValidateCatalog(ctx, input.Metadata.Catalog.Digest, input.Metadata.Catalog.Sequence); err != nil {
		return nil, err
	}
	return newStream(input)
}

func newStream(input Input) (*Stream, error) {
	if len(input.RequestBody) == 0 {
		return nil, errors.New("request proof context is incomplete")
	}
	if input.Metadata.Catalog.Digest == "" {
		return nil, errors.New("catalog digest is required")
	}
	if !proof.ValidCatalogNodeIDs(input.Metadata.Catalog.NodeIDs) {
		return nil, errors.New("all five resolved catalog nodes are required")
	}
	streamingInput := proof.StreamingInput{
		RequestBody: append([]byte(nil), input.RequestBody...),
		Metadata:    input.Metadata,
	}
	return &Stream{
		hasher: proof.NewStreamHasher(streamingInput),
	}, nil
}

func (s *Stream) WriteSentChunk(chunk []byte) {
	if s == nil || s.hasher == nil || len(chunk) == 0 {
		return
	}
	s.hasher.WriteChunk(chunk)
}

func (s *Stream) SetMetadata(metadata proof.Metadata) {
	if s == nil || s.hasher == nil {
		return
	}
	s.hasher.SetMetadata(metadata)
}

func (svc *Service) FinishStream(ctx context.Context, stream *Stream) (*Output, error) {
	if svc == nil || stream == nil {
		return nil, nil
	}
	payload := stream.hasher.FinalPayload()
	if !proof.ValidMetadata(proof.Metadata{
		RequestID:            payload.RequestID,
		NodeID:               payload.NodeID,
		Catalog:              payload.Catalog,
		Pricing:              payload.Pricing,
		Timing:               payload.Timing,
		E2EETranscriptSHA256: payload.Proof.E2EETranscriptSHA256,
	}) {
		return nil, errors.New("response proof metadata is invalid")
	}
	if err := svc.ValidateCatalog(ctx, payload.Catalog.Digest, payload.Catalog.Sequence); err != nil {
		return nil, err
	}
	return svc.outputForPayload(payload)
}
