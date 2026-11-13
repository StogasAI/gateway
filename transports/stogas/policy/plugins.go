package policy

import (
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
)

// ActivePlugins contains the request's selected and decrypted plugin settings.
type ActivePlugins struct {
	Redaction *redaction.Policy
	// TextExtraction is the text extraction mode, one of the TextExtraction constants.
	TextExtraction string
	Export         *exportconfig.Config
}

// TextExtraction returns the strongest text extraction mode that the policy's plugins set, or
// TextExtractionAuto when none sets one: auto differs from off only where off would leave a
// deployment out or refuse a file.
func (c *Config) TextExtraction() string {
	if mode := c.textExtractionSet(); mode != "" {
		return mode
	}
	return TextExtractionAuto
}

// textExtractionSet returns the strongest text extraction mode that the policy's plugins set, or
// "".
func (c *Config) textExtractionSet() string {
	mode := ""
	if c == nil {
		return mode
	}
	parts := c.PluginSources
	if len(parts) == 0 && c.Plugins != nil {
		parts = []*Plugins{c.Plugins}
	}
	for _, part := range parts {
		if part != nil && part.TextExtraction != nil {
			mode = strongerTextExtraction(mode, *part.TextExtraction)
		}
	}
	return mode
}

// MediaTypes returns the policy's input.mediaTypes, or nil.
func (c *Config) MediaTypes() *MediaTypes {
	if c == nil || c.Input == nil {
		return nil
	}
	return c.Input.MediaTypes
}

// InputCheck names the setting that reads all input text, input.asciiOnly or plugins.redaction,
// or returns "" when the policy sets neither. Either refuses an attachment that stays opaque. An
// encrypted redaction that applies counts whatever it holds, since only the request's key opens
// it, so routing and each pair's preparation give the same answer.
func (c *Config) InputCheck() string {
	if c == nil {
		return ""
	}
	if c.Input != nil && c.Input.ASCIIOnly {
		return "input.asciiOnly"
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
			return "plugins.redaction"
		}
	}
	for _, plugins := range c.ActiveEncryptedPlugins {
		if plugins.Units&permissionRedaction != 0 {
			return "plugins.redaction"
		}
	}
	return ""
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
