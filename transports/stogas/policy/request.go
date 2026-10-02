package policy

import (
	"errors"

	"github.com/maximhq/bifrost/transports/stogas/customerkey"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
)

var ErrRequestPolicyDenied = errors.New("request policy is not permitted by this API key")

// Request is compiled once, then applied to each candidate's immutable saved policy.
type Request struct {
	source   *Source
	sections Permission
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
	source, err := document.Open(organizationID, key)
	if err != nil {
		return nil, err
	}
	return &Request{source: source, sections: document.usedSections}, nil
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
	source := request.source
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

func (r *Request) CompileRedaction() (*redaction.Policy, error) {
	if r == nil {
		return nil, nil
	}
	return CompileRedaction(r.source.Config)
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
