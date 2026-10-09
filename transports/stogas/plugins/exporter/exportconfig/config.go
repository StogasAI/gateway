// Package exportconfig owns the portable export policy contract.
package exportconfig

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/http/httpguts"
)

const (
	MaxDestinations = 8
	MaxHeaderBytes  = 8 << 10
)

var ErrConfig = errors.New("invalid export configuration")

type Config struct {
	Destinations []Destination `json:"destinations"`
}

// Destination is immutable after validation. URL is the complete ingestion URL;
// no path is appended. Headers authenticate export delivery, never inference.
type Destination struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
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
	return nil
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
	d.Headers = d.ExportHeaders()
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
