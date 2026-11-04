package policy

import (
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
)

// ActivePlugins contains the request's selected and decrypted plugin settings.
type ActivePlugins struct {
	Redaction      *redaction.Policy
	TextExtraction bool
	Export         *exportconfig.Config
}

func (c *Config) TextExtractionEnabled() bool {
	if c == nil {
		return false
	}
	parts := c.PluginSources
	if len(parts) == 0 && c.Plugins != nil {
		parts = []*Plugins{c.Plugins}
	}
	for _, part := range parts {
		if part != nil && part.TextExtraction != nil && *part.TextExtraction {
			return true
		}
	}
	return false
}

// InspectsInput reports whether the policy, as far as it is unencrypted, inspects input text:
// input limited to ASCII, or redaction. Either refuses an attachment that stays opaque.
// Encrypted redaction is known only once its plugin is opened.
func (c *Config) InspectsInput() bool {
	if c == nil {
		return false
	}
	if c.Input != nil && c.Input.ASCIIOnly {
		return true
	}
	parts := c.PluginSources
	if len(parts) == 0 && c.Plugins != nil {
		parts = []*Plugins{c.Plugins}
	}
	for _, part := range parts {
		if part == nil || part.Redaction == nil {
			continue
		}
		if r := part.Redaction; len(r.Presets) > 0 || len(r.CustomPatterns) > 0 || len(r.Literals) > 0 {
			return true
		}
	}
	return false
}

// ExportConfig retains independent destinations from every applicable source.
func (c *Config) ExportConfig() (*exportconfig.Config, error) {
	if c == nil {
		return nil, nil
	}
	parts := c.PluginSources
	if len(parts) == 0 && c.Plugins != nil {
		parts = []*Plugins{c.Plugins}
	}
	configs := make([]*exportconfig.Config, 0, len(parts))
	for _, p := range parts {
		if p != nil && p.Export != nil {
			configs = append(configs, p.Export)
		}
	}
	if len(configs) == 0 {
		return nil, nil
	}
	return exportconfig.Combine(configs...)
}
