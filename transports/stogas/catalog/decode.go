package catalog

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"time"
)

// shown is a field that readers show and the gateway skips. Naming each one keeps decoding
// strict: a field that the gateway does not know refuses the catalog.
type shown struct{}

func (*shown) UnmarshalJSONFrom(decoder *jsontext.Decoder) error { return decoder.SkipValue() }

// decodeStrict decodes a file of a release, refusing any member that the gateway does not know.
// Records share each distinct price list that prices decodes, so a release decodes each once.
func decodeStrict(data []byte, value any, prices *json.Unmarshalers) error {
	return json.Unmarshal(data, value, json.RejectUnknownMembers(true), json.WithUnmarshalers(prices))
}

func sharedJSON[T any]() *json.Unmarshalers {
	pool := make(map[string]T)
	return json.UnmarshalFromFunc(func(decoder *jsontext.Decoder, destination *T) error {
		raw, err := decoder.ReadValue()
		if err != nil {
			return err
		}
		if existing, ok := pool[string(raw)]; ok {
			*destination = existing
			return nil
		}
		var value T
		if err := json.Unmarshal(raw, &value, json.RejectUnknownMembers(true)); err != nil {
			return err
		}
		pool[string(raw)] = value
		*destination = value
		return nil
	})
}

// catalogRoot is a release's root: a summary of every record, current or retired, the parts
// that hold the records that are not whole in it, and the dated states.
type catalogRoot struct {
	Schema    string        `json:"schema"`
	Summaries rootSummaries `json:"summaries"`
	Parts     []PartFile    `json:"parts"`
	Periods   shown         `json:"periods"`
	Schedule  []rootState   `json:"schedule"`
}

// rootSummaries holds the authors and providers whole.
type rootSummaries struct {
	Authors     map[string]compiledAuthor   `json:"authors"`
	Groups      map[string]groupSummary     `json:"groups"`
	Models      map[string]summary          `json:"models"`
	Providers   map[string]compiledProvider `json:"providers"`
	Routes      map[string]summary          `json:"routes"`
	Deployments map[string]summary          `json:"deployments"`
}

// summary is what the gateway reads of a model, route or deployment in the root: the part that
// holds it, the date that it retires, and a model's aliases, which still name it once it
// retires. The rest repeat the record.
type summary struct {
	AuthorID    shown `json:"authorId"`
	DerivedFrom shown `json:"derivedFrom"`
	GroupIDs    shown `json:"groupIds"`
	Interfaces  shown `json:"interfaces"`
	ModelID     shown `json:"modelId"`
	Name        shown `json:"name"`
	ProviderID  shown `json:"providerId"`
	ReleaseDate shown `json:"releaseDate"`
	RouteIDs    shown `json:"routeIds"`

	Aliases        []string `json:"aliases"`
	Part           int      `json:"part"`
	RetirementDate *string  `json:"retirementDate"`
}

// groupSummary is what the gateway reads of a group: the groups that contain it. A model is in
// each group that it names and in every group that contains one of them.
type groupSummary struct {
	AuthorID       shown `json:"authorId"`
	Name           shown `json:"name"`
	RetirementDate shown `json:"retirementDate"`

	ParentIDs []string `json:"parentIds"`
}

// rootState is a dated state as the root lists it: when it starts, and the summaries that
// differ then. The parts hold the records that differ.
type rootState struct {
	Start     string `json:"start"`
	Summaries struct {
		Authors     map[string]compiledAuthor   `json:"authors"`
		Groups      shown                       `json:"groups"`
		Models      shown                       `json:"models"`
		Providers   map[string]compiledProvider `json:"providers"`
		Routes      shown                       `json:"routes"`
		Deployments shown                       `json:"deployments"`
	} `json:"summaries"`
}

// catalogPart holds some of a release's models, routes and deployments, and how they differ in
// each dated state that changes them.
type catalogPart struct {
	Schema   string    `json:"schema"`
	Graph    partGraph `json:"graph"`
	Schedule []struct {
		Start string    `json:"start"`
		Graph partGraph `json:"graph"`
	} `json:"schedule"`
}

type partGraph struct {
	Models      map[string]compiledModel       `json:"models"`
	Routes      map[string]compiledRoute       `json:"routes"`
	Deployments map[string]*compiledDeployment `json:"deployments"`
}

// compiledCatalog is a release as the gateway reads it at an instant: the graph, how each dated
// state changes it, and the day that each selector of a record that has retired retired.
type compiledCatalog struct {
	Graph    compiledGraph     `json:"graph"`
	Schedule []scheduleEntry   `json:"schedule"`
	Retired  map[string]string `json:"retired"`
}

// A schedule entry lists every node that differs from the base graph from Start until the
// next entry starts.
type scheduleEntry struct {
	Start time.Time     `json:"start"`
	Graph compiledGraph `json:"graph"`
}
