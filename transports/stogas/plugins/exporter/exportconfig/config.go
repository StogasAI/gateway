// Package exportconfig owns the portable export policy contract.
package exportconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"net/textproto"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"
)

const (
	// MaxDestinations bounds one policy, counting its rules. The policies of a
	// request combine without a total of their own, as GitHub bounds the
	// webhooks of an organization and of a repository and delivers to both.
	MaxDestinations = 8
	MaxHeaderBytes  = 8 << 10
)

// FormatOTLP posts each record as one OTLP/HTTP trace export in binary Protobuf, whose spans
// carry the attributes of the OpenTelemetry GenAI semantic conventions 1.41. Those conventions
// are in development and rename attributes between versions, so the value names the version: a
// later version takes a new value, and this one keeps its attributes.
const FormatOTLP = "otlp-genai-1.41"

var ErrConfig = errors.New("invalid export configuration")

type Config struct {
	Destinations []Destination `json:"destinations"`
}

// Destination is immutable after validation. URL is the complete ingestion URL;
// no path is appended. Headers authenticate export delivery, never inference.
// Format empty posts the record as JSON. Sample nil sends every record, and
// Content nil sends each of them with its request and response bodies.
type Destination struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Format  string            `json:"format,omitempty"`
	Content *Content          `json:"content,omitempty"`
	Sample  *Sample           `json:"sample,omitempty"`
}

// Outcomes are how a request ended, as its record and Analytics name it.
var Outcomes = [...]string{"success", "failed", "cancelled", "rejected", "unknown"}

// Sample is the share of each outcome's records that a destination gets, in
// the order of Outcomes. A policy writes one rate for every outcome, or an
// object with a rate for each outcome that the destination gets at all.
type Sample [len(Outcomes)]float64

func (s *Sample) UnmarshalJSON(raw []byte) error {
	var rate float64
	if json.Unmarshal(raw, &rate) == nil && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		for i := range s {
			s[i] = rate
		}
		return s.validate()
	}
	var rates map[string]float64
	if json.Unmarshal(raw, &rates) != nil {
		return ErrConfig
	}
	*s = Sample{}
	for name, rate := range rates {
		i := outcomeIndex(name)
		// A listed outcome is one that the destination gets.
		if i < 0 || rate == 0 {
			return ErrConfig
		}
		s[i] = rate
	}
	return s.validate()
}

func (s Sample) MarshalJSON() ([]byte, error) {
	uniform := true
	rates := make(map[string]float64, len(s))
	for i, rate := range s {
		uniform = uniform && rate == s[0]
		if rate > 0 {
			rates[Outcomes[i]] = rate
		}
	}
	if uniform {
		return json.Marshal(s[0])
	}
	return json.Marshal(rates)
}

// Content is the share of each outcome's records that carry request and
// response bodies. A policy writes true or false for every record or none, or
// a share as a sample writes it. A destination gets no bodies for a record
// that its sample leaves out.
type Content Sample

func (c *Content) UnmarshalJSON(raw []byte) error {
	var every bool
	if json.Unmarshal(raw, &every) == nil && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		*c = Content{}
		if every {
			*c = Content(everyRecord)
		}
		return nil
	}
	return (*Sample)(c).UnmarshalJSON(raw)
}

func (c Content) MarshalJSON() ([]byte, error) {
	switch Sample(c) {
	case everyRecord:
		return []byte("true"), nil
	case Sample{}:
		return []byte("false"), nil
	}
	return Sample(c).MarshalJSON()
}

var everyRecord = Sample{1, 1, 1, 1, 1}

func (s *Sample) validate() error {
	sends := false
	for _, rate := range s {
		// The comparison also refuses a rate that is not a number.
		if !(rate >= 0 && rate <= 1) {
			return ErrConfig
		}
		sends = sends || rate > 0
	}
	if !sends {
		return ErrConfig
	}
	return nil
}

func outcomeIndex(outcome string) int {
	for i, name := range Outcomes {
		if name == outcome {
			return i
		}
	}
	return -1
}

// Rate is the share of an outcome's records that the destination gets.
func (d Destination) Rate(outcome string) float64 {
	if d.Sample == nil {
		return 1
	}
	if i := outcomeIndex(outcome); i >= 0 {
		return d.Sample[i]
	}
	return 0
}

// ContentRate is the share of an outcome's records that the destination gets
// with bodies.
func (d Destination) ContentRate(outcome string) float64 {
	rate := d.Rate(outcome)
	if d.Content == nil {
		return rate
	}
	if i := outcomeIndex(outcome); i >= 0 {
		return min(rate, d.Content[i])
	}
	return 0
}

// shares are the destination's rates of records and of records with bodies,
// for each outcome.
func (d Destination) shares() (records, bodies Sample) {
	for i, outcome := range Outcomes {
		records[i], bodies[i] = d.Rate(outcome), d.ContentRate(outcome)
	}
	return records, bodies
}

// withShares writes the rates as a policy would: no sample for every record,
// and no content for bodies on each record that the destination gets.
func (d Destination) withShares(records, bodies Sample) Destination {
	d.Sample, d.Content = nil, nil
	if records != everyRecord {
		d.Sample = &records
	}
	if bodies != records {
		d.Content = (*Content)(&bodies)
	}
	return d
}

// Reach is the highest rate of any outcome: a request at or above it gets no
// record from the destination however it ends.
func (d Destination) Reach() float64 {
	records, _ := d.shares()
	return slices.Max(records[:])
}

// ContentReach is the highest rate of bodies of any outcome: a request at or
// above it sends the destination no bodies however it ends.
func (d Destination) ContentReach() float64 {
	_, bodies := d.shares()
	return slices.Max(bodies[:])
}

// Position places a request in [0, 1) by the first 32 bits of the SHA-256 of
// its ID. A destination gets the record of a request whose position is below
// its rate for the outcome. The gateway makes the ID, so a caller cannot choose
// the position, and every destination reads the same one: a higher rate gets
// every record that a lower rate gets, and the highest rate of several
// destinations gets exactly the records that any of them gets.
func Position(requestID string) float64 {
	sum := sha256.Sum256([]byte(requestID))
	return float64(binary.BigEndian.Uint32(sum[:4])) / (1 << 32)
}

func (c *Config) Validate() error {
	if c == nil {
		return nil
	}
	if c.Destinations == nil || len(c.Destinations) > MaxDestinations {
		return ErrConfig
	}
	for i := range c.Destinations {
		if err := c.Destinations[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (d *Destination) Validate() error {
	u, err := url.Parse(d.URL)
	if err != nil || len(d.URL) > 2048 || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ErrConfig
	}
	// Loopback HTTP is accepted by the schema for local receivers. The runtime
	// permits it only in local development; hosted delivery requires public HTTPS.
	if u.Scheme == "http" {
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || !ip.IsLoopback() {
			return ErrConfig
		}
	}
	headerBytes := 0
	seen := map[string]bool{}
	for name, value := range d.Headers {
		key := strings.ToLower(name)
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) || seen[key] {
			return ErrConfig
		}
		switch key {
		case "host", "connection", "content-length", "content-type", "content-encoding", "transfer-encoding", "trailer", "te", "upgrade", "proxy-authorization", "proxy-connection", "accept-encoding", "idempotency-key":
			return ErrConfig
		}
		seen[key] = true
		headerBytes += len(name) + len(value)
	}
	if headerBytes > MaxHeaderBytes || len(d.Headers) > 32 {
		return ErrConfig
	}
	if d.Format != "" && d.Format != FormatOTLP {
		return ErrConfig
	}
	if d.Content != nil {
		for _, rate := range d.Content {
			if !(rate >= 0 && rate <= 1) {
				return ErrConfig
			}
		}
	}
	if d.Sample != nil {
		return d.Sample.validate()
	}
	return nil
}

// Combine unions independent required destinations. The same URL, headers and
// format name one receiver, which gets one record: two would share an Idempotency-Key.
// It gets that record if any duplicate does, and with bodies if a duplicate
// that gets the record sends them. Every destination reads the same position,
// so the highest rate of each outcome says exactly that, for records and for
// bodies. A descendant can therefore neither withhold records or bodies from
// an inherited destination nor alter its credentials. The union has no bound
// of its own: MaxDestinations bounds each policy.
func Combine(configs ...*Config) (*Config, error) {
	result := &Config{Destinations: []Destination{}}
	seen := map[[32]byte]int{}
	for _, c := range configs {
		if err := c.Validate(); err != nil {
			return nil, err
		}
		if c == nil {
			continue
		}
		for _, d := range c.Destinations {
			id := d.Identity()
			records, bodies := d.shares()
			i, found := seen[id]
			if !found {
				seen[id] = len(result.Destinations)
				result.Destinations = append(result.Destinations, d.withShares(records, bodies))
				continue
			}
			keptRecords, keptBodies := result.Destinations[i].shares()
			for outcome := range records {
				records[outcome] = max(records[outcome], keptRecords[outcome])
				bodies[outcome] = max(bodies[outcome], keptBodies[outcome])
			}
			result.Destinations[i] = result.Destinations[i].withShares(records, bodies)
		}
	}
	return result, nil
}

func (d Destination) Identity() [32]byte {
	d.Headers, d.Content, d.Sample = d.ExportHeaders(), nil, nil
	b, _ := json.Marshal(d)
	return sha256.Sum256(b)
}

func (d Destination) ExportHeaders() map[string]string {
	result := make(map[string]string, len(d.Headers))
	for name, value := range d.Headers {
		// http.CanonicalHeaderKey calls this, but importing net/http here would add 1.4 MB to
		// the policy compiler's WebAssembly.
		result[textproto.CanonicalMIMEHeaderKey(name)] = value
	}
	return result
}
