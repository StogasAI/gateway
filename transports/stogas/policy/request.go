package policy

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
)

var ErrRequestPolicyDenied = errors.New("request policy is not permitted by this API key")

// Request is compiled once, then applied to each candidate's immutable saved
// policy. An encrypted request policy is decrypted only after a candidate's
// saved policy permits every section it sets, and then once for all of them.
type Request struct {
	sections  Permission
	source    *Source
	open      func() (*Source, error)
	permitted atomic.Bool
}

func CompileRequest(raw []byte, organizationID string, key customerkey.Keys) (*Request, error) {
	if len(raw) == 0 || len(raw) > 16<<10 {
		return nil, configError("request policy exceeds the size limit")
	}
	document, err := ParseSourceDocument(raw)
	if err != nil {
		return nil, err
	}
	if document.usedSections&^requestPermissions != 0 {
		return nil, configError("request policies cannot set limits, delegation, or encryption settings")
	}
	request := &Request{sections: document.usedSections}
	if document.Encrypted() {
		request.open = sync.OnceValues(func() (*Source, error) { return document.Open(organizationID, key) })
		return request, nil
	}
	request.source, err = document.Open(organizationID, key)
	if err != nil {
		return nil, err
	}
	return request, nil
}

// opened returns the request's source, decrypting it on first use. Callers
// check permission first.
func (r *Request) opened() (*Source, error) {
	if r.open == nil {
		return r.source, nil
	}
	return r.open()
}

// ApplyRequest returns a new immutable configuration. Request settings never
// modify a cached saved policy or remove its restrictions.
func ApplyRequest(parent *Config, request *Request) (*Config, error) {
	if request == nil {
		return parent, nil
	}
	if parent == nil || request.sections&^Permission(parent.RequestPermission) != 0 {
		return nil, ErrRequestPolicyDenied
	}
	request.permitted.Store(true)
	source, err := request.opened()
	if err != nil {
		return nil, err
	}
	if source.RequiredEncryptionKeyID != "" && !customerkey.Registered(parent.EncryptionKeys, source.RequiredEncryptionKeyID) {
		return nil, customerkey.ErrKey
	}
	if len(parent.sources) == 0 {
		return nil, configError("request policies require compiled saved sources")
	}
	sources := append([]ScopedSource{}, parent.sources...)
	sources = append(sources, ScopedSource{Scope: RequestScope, Value: source})
	return ComposeSources(sources)
}

// CompileRedaction compiles the request policy's redaction once ApplyRequest
// has permitted it.
func (r *Request) CompileRedaction() (*redaction.Policy, error) {
	if r == nil {
		return nil, nil
	}
	if !r.permitted.Load() {
		return nil, ErrRequestPolicyDenied
	}
	source, err := r.opened()
	if err != nil {
		return nil, err
	}
	return CompileRedaction(source.Config)
}

func intersectAllowedNodes(parent, child *AllowedCatalogNodes) *AllowedCatalogNodes {
	if child == nil {
		return parent
	}
	if parent == nil {
		return child
	}
	return &AllowedCatalogNodes{
		Authors: intersectIDs(parent.Authors, child.Authors), Models: intersectIDs(parent.Models, child.Models),
		Deployments: intersectIDs(parent.Deployments, child.Deployments), Routes: intersectIDs(parent.Routes, child.Routes),
		Providers: intersectIDs(parent.Providers, child.Providers),
	}
}
func intersectIDs(parent, child []string) []string {
	if child == nil {
		return parent
	}
	if parent == nil {
		return child
	}
	allowed := make(map[string]bool, len(child))
	for _, id := range child {
		allowed[id] = true
	}
	out := make([]string, 0, len(parent))
	for _, id := range parent {
		if allowed[id] {
			out = append(out, id)
		}
	}
	return out
}
