// Package exportconfig owns the portable export policy contract.
package exportconfig

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"
)

const (
	MaxDestinations     = 8
	DefaultCaptureBytes = 64 << 10
	MaxCaptureBytes     = 256 << 10
	MaxHeaderBytes      = 8 << 10
)

var ErrConfig = errors.New("invalid export configuration")

type Config struct {
	Destinations []Destination `json:"destinations"`
}

type StatusRange struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// Destination is immutable after validation. URL is the complete ingestion URL;
// no path is appended. Headers authenticate export delivery, never inference.
type Destination struct {
	URL               string            `json:"url"`
	Format            string            `json:"format,omitempty"`
	Encoding          string            `json:"encoding,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	Content           string            `json:"content,omitempty"`
	MaxCaptureBytes   *int              `json:"maxCaptureBytes,omitempty"`
	MaxRetries        *int              `json:"maxRetries,omitempty"`
	SampleRate        *float64          `json:"sampleRate,omitempty"`
	Outcomes          []string          `json:"outcomes,omitempty"`
	ErrorStatusRanges []StatusRange     `json:"errorStatusRanges,omitempty"`
	ErrorCodes        []string          `json:"errorCodes,omitempty"`
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
	if d.Format != "" && d.Format != "otlp" && d.Format != "webhook" {
		return ErrConfig
	}
	if d.Encoding != "" && d.Encoding != "json" && d.Encoding != "protobuf" {
		return ErrConfig
	}
	if d.Format == "webhook" && d.Encoding == "protobuf" {
		return ErrConfig
	}
	if d.Content != "" && d.Content != "none" && d.Content != "input" && d.Content != "output" && d.Content != "both" {
		return ErrConfig
	}
	if d.MaxCaptureBytes != nil && (*d.MaxCaptureBytes < 1 || *d.MaxCaptureBytes > MaxCaptureBytes) {
		return ErrConfig
	}
	if d.MaxRetries != nil && (*d.MaxRetries < 0 || *d.MaxRetries > 3) {
		return ErrConfig
	}
	if d.SampleRate != nil && (math.IsNaN(*d.SampleRate) || math.IsInf(*d.SampleRate, 0) || *d.SampleRate < 0 || *d.SampleRate > 1) {
		return ErrConfig
	}
	if d.Outcomes != nil && (len(d.Outcomes) == 0 || len(d.Outcomes) > 3) {
		return ErrConfig
	}
	seen := map[string]bool{}
	for _, outcome := range d.Outcomes {
		if (outcome != "success" && outcome != "failure" && outcome != "cancelled") || seen[outcome] {
			return ErrConfig
		}
		seen[outcome] = true
	}
	if d.ErrorStatusRanges != nil && (len(d.ErrorStatusRanges) == 0 || len(d.ErrorStatusRanges) > 8) {
		return ErrConfig
	}
	for _, r := range d.ErrorStatusRanges {
		if r.Min < 400 || r.Max > 599 || r.Min > r.Max {
			return ErrConfig
		}
	}
	if d.ErrorCodes != nil && (len(d.ErrorCodes) == 0 || len(d.ErrorCodes) > 32) {
		return ErrConfig
	}
	seen = map[string]bool{}
	for _, code := range d.ErrorCodes {
		if len(code) == 0 || len(code) > 128 || seen[code] {
			return ErrConfig
		}
		for _, c := range code {
			if c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return ErrConfig
			}
		}
		seen[code] = true
	}
	if (len(d.ErrorCodes) > 0 || len(d.ErrorStatusRanges) > 0) && len(d.Outcomes) > 0 && !slices.Contains(d.Outcomes, "failure") {
		return ErrConfig
	}
	headerBytes := 0
	seen = map[string]bool{}
	for name, value := range d.Headers {
		key := strings.ToLower(name)
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) || seen[key] {
			return ErrConfig
		}
		switch key {
		case "host", "connection", "content-length", "content-type", "content-encoding", "transfer-encoding", "trailer", "te", "upgrade", "proxy-authorization", "proxy-connection", "accept-encoding":
			return ErrConfig
		}
		seen[key] = true
		headerBytes += len(name) + len(value)
	}
	if headerBytes > MaxHeaderBytes || len(d.Headers) > 32 {
		return ErrConfig
	}
	return nil
}

func (d Destination) CaptureLimit() int {
	if d.MaxCaptureBytes != nil {
		return *d.MaxCaptureBytes
	}
	return DefaultCaptureBytes
}
func (d Destination) Retries() int {
	if d.MaxRetries != nil {
		return *d.MaxRetries
	}
	return 3
}
func (d Destination) Rate() float64 {
	if d.SampleRate != nil {
		return *d.SampleRate
	}
	return 1
}
func (d Destination) InputEnabled() bool  { return d.Content == "input" || d.Content == "both" }
func (d Destination) OutputEnabled() bool { return d.Content == "output" || d.Content == "both" }
func (d Destination) Match(outcome string, status int, code string) bool {
	if len(d.Outcomes) > 0 && !slices.Contains(d.Outcomes, outcome) {
		return false
	}
	if outcome != "failure" {
		return true
	}
	if len(d.ErrorCodes) > 0 && !slices.Contains(d.ErrorCodes, code) {
		return false
	}
	if len(d.ErrorStatusRanges) > 0 {
		for _, r := range d.ErrorStatusRanges {
			if status >= r.Min && status <= r.Max {
				return true
			}
		}
		return false
	}
	return true
}

// Combine unions independent required destinations and removes exact duplicates.
// A descendant cannot alter an inherited destination or its credentials.
func Combine(configs ...*Config) (*Config, error) {
	result := &Config{Destinations: []Destination{}}
	seen := map[[32]byte]bool{}
	for _, c := range configs {
		if err := c.Validate(); err != nil {
			return nil, err
		}
		if c == nil {
			continue
		}
		for _, d := range c.Destinations {
			id := d.Identity()
			if !seen[id] {
				seen[id] = true
				result.Destinations = append(result.Destinations, d)
			}
		}
	}
	if len(result.Destinations) > MaxDestinations {
		return nil, ErrConfig
	}
	return result, nil
}

func (d Destination) Identity() [32]byte {
	// Materialize defaults and canonical header names before deduplication.
	if d.Format == "" {
		d.Format = "otlp"
	}
	if d.Encoding == "" {
		d.Encoding = "json"
	}
	if d.Content == "" {
		d.Content = "none"
	}
	limit, retries, rate := d.CaptureLimit(), d.Retries(), d.Rate()
	d.MaxCaptureBytes, d.MaxRetries, d.SampleRate = &limit, &retries, &rate
	d.Headers = d.ExportHeaders()
	d.Outcomes = slices.Clone(d.Outcomes)
	slices.Sort(d.Outcomes)
	d.ErrorCodes = slices.Clone(d.ErrorCodes)
	slices.Sort(d.ErrorCodes)
	d.ErrorStatusRanges = slices.Clone(d.ErrorStatusRanges)
	slices.SortFunc(d.ErrorStatusRanges, func(a, b StatusRange) int {
		if a.Min != b.Min {
			return a.Min - b.Min
		}
		return a.Max - b.Max
	})
	b, _ := json.Marshal(d)
	return sha256.Sum256(b)
}

func (d Destination) ExportHeaders() map[string]string {
	result := make(map[string]string, len(d.Headers))
	for name, value := range d.Headers {
		result[http.CanonicalHeaderKey(name)] = value
	}
	return result
}
