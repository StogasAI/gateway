package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

var ErrRequestPolicyDenied = errors.New("request policy is not permitted by this API key")

// ApplyRequest returns a new immutable configuration. A cached key policy must
// never retain request filters or ordering from one client request to the next.
func ApplyRequest(parent *Config, raw []byte) (*Config, error) {
	if parent == nil || (parent.Routing.RequestPolicy != "filter" && parent.Routing.RequestPolicy != "filter_and_sort") {
		return nil, ErrRequestPolicyDenied
	}
	if len(raw) == 0 || len(raw) > 16<<10 {
		return nil, configError("request policy exceeds the size limit")
	}
	var request struct {
		Version int `json:"version"`
		Routing *struct {
			Query   *string              `json:"query"`
			Allowed *AllowedCatalogNodes `json:"allowedCatalogNodes"`
		} `json:"routing"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return nil, configError("invalid request policy: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, configError("request policy has trailing JSON")
	}
	if request.Version != 1 || request.Routing == nil || (request.Routing.Query == nil && request.Routing.Allowed == nil) {
		return nil, configError("request policy requires version 1 and a routing query or allowed catalog nodes")
	}
	// Null is not a way to remove a parent restriction.
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, configError("invalid request policy")
	}
	if len(object) != 2 || object["version"] == nil || object["routing"] == nil {
		return nil, configError("request policy fields must be version and routing")
	}
	var routing map[string]json.RawMessage
	if err := json.Unmarshal(object["routing"], &routing); err != nil {
		return nil, configError("invalid request routing")
	}
	for name, value := range routing {
		if name != "query" && name != "allowedCatalogNodes" {
			return nil, configError("unknown request routing field")
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, configError("request routing fields cannot be null")
		}
	}
	var child *Query
	if request.Routing.Query != nil {
		var err error
		child, err = CompileQuery(*request.Routing.Query)
		if err != nil {
			return nil, err
		}
		if parent.Routing.RequestPolicy == "filter" && len(child.OrderBy) > 0 {
			return nil, ErrRequestPolicyDenied
		}
	}
	if a := request.Routing.Allowed; a != nil {
		if err := a.validate(); err != nil {
			return nil, err
		}
		if len(a.Authors)+len(a.Models)+len(a.Deployments)+len(a.Routes)+len(a.Providers) > 64 {
			return nil, configError("request policy exceeds the allowed catalog node limit")
		}
		var lists map[string]json.RawMessage
		if err := json.Unmarshal(routing["allowedCatalogNodes"], &lists); err != nil {
			return nil, configError("invalid catalog node lists")
		}
		for name, value := range lists {
			switch name {
			case "authors", "models", "deployments", "routes", "providers":
			default:
				return nil, configError("unknown catalog node list")
			}
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return nil, configError("catalog node lists cannot be null")
			}
		}
	}
	out := *parent
	out.Routing = parent.Routing
	out.Routing.Query = intersectQueries(parent.Routing.Query, child)
	out.Routing.AllowedCatalogNodes = intersectAllowedNodes(parent.Routing.AllowedCatalogNodes, request.Routing.Allowed)
	if err := out.Routing.Query.validate(); err != nil {
		return nil, err
	}
	if err := out.Routing.AllowedCatalogNodes.validate(); err != nil {
		return nil, err
	}
	return &out, nil
}

func intersectQueries(parent, child *Query) *Query {
	if child == nil {
		return parent
	}
	if parent == nil {
		return child
	}
	out := &Query{Where: parent.Where, OrderBy: append([]Sort{}, parent.OrderBy...)}
	if child.Where != nil {
		if out.Where == nil {
			out.Where = child.Where
		} else {
			operands := []*Expression{out.Where}
			if out.Where.Kind == "and" {
				operands = append([]*Expression{}, out.Where.Operands...)
			}
			out.Where = &Expression{Kind: "and", Operands: append(operands, child.Where)}
		}
	}
	for _, item := range child.OrderBy {
		if len(out.OrderBy) > 0 && out.OrderBy[len(out.OrderBy)-1].Path == "deployment.id" {
			break
		}
		found := false
		for _, existing := range out.OrderBy {
			if existing.Path == item.Path {
				found = true
				break
			}
		}
		if !found {
			out.OrderBy = append(out.OrderBy, item)
		}
	}
	return out
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
	out := make([]string, 0, len(parent))
	for _, id := range parent {
		if allowedNode(child, id) {
			out = append(out, id)
		}
	}
	return out
}
