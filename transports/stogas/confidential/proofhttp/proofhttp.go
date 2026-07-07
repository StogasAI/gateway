package proofhttp

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
	"github.com/maximhq/bifrost/transports/stogas/confidential/quote"
	"github.com/maximhq/bifrost/transports/stogas/confidential/reportdata"
)

const (
	HeaderQuote                 = "X-Stogas-Quote"
	HeaderReportData            = "X-Stogas-Report-Data"
	HeaderResolvedCatalogNodeID = "X-Stogas-Resolved-Catalog-Node-Ids"
	HeaderProcessedHash         = "X-Stogas-Processed-Hash"
	HeaderProcessedSignature    = "X-Stogas-Processed-Signature"
	SSEEventName                = "stogas.proof"
)

type SnapshotProvider interface {
	Current(ctx context.Context) (*quote.Snapshot, error)
}

type Service struct {
	Quotes SnapshotProvider
	Signer ed25519.PrivateKey
}

type Input struct {
	CatalogNodeIDs       []string
	ProcessedRequestJSON []byte
	ResponseJSON         []byte
}

type Output struct {
	Headers map[string]string
	Object  Object
}

type Object struct {
	ProcessedHash          string             `json:"processed_hash"`
	ProcessedSignature     string             `json:"processed_signature"`
	Quote                  string             `json:"quote"`
	ReportData             reportdata.Payload `json:"report_data"`
	ResolvedCatalogNodeIDs []string           `json:"resolved_catalog_node_ids"`
}

func (s *Service) Build(ctx context.Context, input Input) (*Output, error) {
	if s == nil {
		return nil, nil
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	if len(input.ProcessedRequestJSON) == 0 {
		return nil, errors.New("processed request JSON is required")
	}
	if len(input.ResponseJSON) == 0 {
		return nil, errors.New("response JSON is required")
	}
	if len(input.CatalogNodeIDs) == 0 {
		return nil, errors.New("resolved catalog node ids are required")
	}
	snapshot, err := s.currentValidatedSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	processedHash, err := proof.Hash(proof.Input{
		ProcessedRequestJSON: append([]byte(nil), input.ProcessedRequestJSON...),
		ResponseJSON:         append([]byte(nil), input.ResponseJSON...),
		CatalogNodeIDs:       append([]string(nil), input.CatalogNodeIDs...),
	})
	if err != nil {
		return nil, err
	}
	return s.outputForHash(snapshot, input.CatalogNodeIDs, processedHash)
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

func (s *Service) outputForHash(snapshot *quote.Snapshot, catalogNodeIDs []string, processedHash string) (*Output, error) {
	canonicalReportData, err := reportdata.CanonicalJSON(snapshot.Payload)
	if err != nil {
		return nil, err
	}
	signature := proof.Sign(s.Signer, processedHash)
	object := Object{
		ProcessedHash:          processedHash,
		ProcessedSignature:     signature,
		Quote:                  base64.RawURLEncoding.EncodeToString(snapshot.Quote),
		ReportData:             snapshot.Payload,
		ResolvedCatalogNodeIDs: append([]string(nil), catalogNodeIDs...),
	}
	return &Output{
		Headers: map[string]string{
			HeaderQuote:                 object.Quote,
			HeaderReportData:            base64.RawURLEncoding.EncodeToString(canonicalReportData),
			HeaderResolvedCatalogNodeID: strings.Join(catalogNodeIDs, ","),
			HeaderProcessedHash:         object.ProcessedHash,
			HeaderProcessedSignature:    object.ProcessedSignature,
		},
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
	_, err := s.currentValidatedSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	return newStream(input)
}

func newStream(input Input) (*Stream, error) {
	if len(input.ProcessedRequestJSON) == 0 {
		return nil, errors.New("processed request JSON is required")
	}
	if len(input.CatalogNodeIDs) == 0 {
		return nil, errors.New("resolved catalog node ids are required")
	}
	return &Stream{
		base: input,
		hasher: proof.NewStreamHasher(proof.StreamingInput{
			ProcessedRequestJSON: append([]byte(nil), input.ProcessedRequestJSON...),
			CatalogNodeIDs:       append([]string(nil), input.CatalogNodeIDs...),
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
	hash, err := stream.hasher.FinalHash()
	if err != nil {
		return nil, err
	}
	return svc.outputForHash(snapshot, stream.base.CatalogNodeIDs, hash)
}
