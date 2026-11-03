package proofhttp

import (
	"context"
	"encoding/json"
	"errors"

	verifier "github.com/StogasAI/stogas/go"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
)

const SSECommentPrefix = "stogas "

type Service struct {
	keys   *verifier.NodeKeys
	boot   [32]byte
	nodeID string
}

type Input = proof.Input
type Output struct {
	// JSON is the bag that the caller receives, salts included.
	JSON []byte
	// Export is the bag for logs and exports, which never hold the salts.
	Export []byte
	Object proof.Object
}

// New binds receipts to the logged boot that commits these keys, after the
// runtime has verified it and taken its node identity from that verification.
func New(bootSHA256 [32]byte, nodeID string, keys *verifier.NodeKeys) (*Service, error) {
	if keys == nil || nodeID == "" {
		return nil, errors.New("invalid receipt identity")
	}
	return &Service{keys: keys, boot: bootSHA256, nodeID: nodeID}, nil
}

func (s *Service) Build(ctx context.Context, input Input) (*Output, error) {
	if s == nil {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if input.RequestDigest == nil || len(input.ResponseBody) == 0 {
		return nil, errors.New("receipt content is empty")
	}
	response, err := verifier.ResponseDigest(input.ResponseBody)
	if err != nil {
		return nil, err
	}
	return s.output(input.Metadata, verifier.ContentDigest(*input.RequestDigest), response)
}

func (s *Service) output(metadata proof.Metadata, request, response verifier.ContentDigest) (*Output, error) {
	if s.nodeID == "" || !proof.ValidMetadata(metadata) {
		return nil, errors.New("receipt metadata or identity is invalid")
	}
	object := proof.Object{Metadata: metadata, NodeID: s.nodeID}
	unsigned, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	signed, err := s.keys.SignReceipt(s.boot, request, response, unsigned)
	if err != nil {
		return nil, err
	}
	var parts struct {
		Receipt proof.Receipt `json:"receipt"`
		Salts   proof.Salts   `json:"salts"`
	}
	if err := json.Unmarshal(signed, &parts); err != nil {
		return nil, err
	}
	object.Receipt = parts.Receipt
	export, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	object.Salts = &parts.Salts
	encoded, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	if len(encoded) > proof.MaxObjectBytes {
		return nil, errors.New("response metadata exceeds its encoded size limit")
	}
	return &Output{JSON: encoded, Export: export, Object: object}, nil
}

// Stream belongs to one response writer. It retains digests and the response that the
// stream's events carry, never request bodies. Close it when the stream ends.
type Stream struct {
	request  verifier.ContentDigest
	content  *verifier.StreamContent
	err      error
	metadata proof.Metadata
	finished bool
}

func (s *Service) NewStream(ctx context.Context, input Input) (*Stream, error) {
	if s == nil {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.nodeID == "" || s.keys == nil || input.RequestDigest == nil || !proof.ValidCatalog(input.Metadata.Catalog) {
		return nil, errors.New("receipt context is incomplete")
	}
	return &Stream{request: verifier.ContentDigest(*input.RequestDigest), content: verifier.NewStreamContent(), metadata: input.Metadata}, nil
}

// SentEvent reads one complete event as the caller receives it. A block of comments, such as
// a keepalive or the receipt, changes nothing.
func (s *Stream) SentEvent(event []byte) {
	if s != nil && !s.finished && s.err == nil {
		s.err = s.content.Push(event)
	}
}

// Close releases the response that the stream's events assembled to.
func (s *Stream) Close() {
	if s != nil {
		s.content.Close()
	}
}
func (s *Stream) SetMetadata(metadata proof.Metadata) {
	if s != nil && !s.finished {
		s.metadata = metadata
	}
}
func (s *Service) FinishStream(ctx context.Context, stream *Stream) (*Output, error) {
	if s == nil || stream == nil {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if stream.finished {
		return nil, errors.New("receipt stream is already finished")
	}
	stream.finished = true
	defer stream.Close()
	if stream.err != nil {
		return nil, stream.err
	}
	response, err := stream.content.Digest()
	if err != nil {
		return nil, err
	}
	return s.output(stream.metadata, stream.request, response)
}

// Close is called after all admitted requests finish.
func (s *Service) Close() {
	if s != nil {
		s.keys = nil
	}
}
