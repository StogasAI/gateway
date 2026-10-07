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
		if part != nil && part.StogasTextExtraction != nil && *part.StogasTextExtraction {
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
		if p != nil && p.StogasExport != nil {
			configs = append(configs, p.StogasExport)
		}
	}
	if len(configs) == 0 {
		return nil, nil
	}
	return exportconfig.Combine(configs...)
}
