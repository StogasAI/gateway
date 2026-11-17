package policy

import (
	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
	"github.com/maximhq/bifrost/transports/stogas/plugins/redaction"
)

// ActivePlugins contains the request's selected and decrypted plugin settings.
type ActivePlugins struct {
	Redaction *redaction.Policy
	// TextExtraction gives each file its text extraction mode.
	TextExtraction TextExtraction
	Export         *exportconfig.Config
}

// TextExtraction returns the text extraction settings of the policy's plugins as one set, which
// gives each file the strongest mode that any of them sets for it, or nil when they set none.
func (c *Config) TextExtraction() TextExtraction {
	if c == nil {
		return nil
	}
	parts := c.PluginSources
	if len(parts) == 0 && c.Plugins != nil {
		parts = []*Plugins{c.Plugins}
	}
	return combineTextExtraction(parts)
}

// combineTextExtraction returns one set that gives each file the strongest mode that the parts
// set for it, or nil when they set none. A part's media type decides for its files in place of
// that part's family, so a key combines what each part gives the key's files, and the set shares
// a single part's settings.
func combineTextExtraction(parts []*Plugins) TextExtraction {
	var sets []TextExtraction
	for _, part := range parts {
		if part != nil && part.TextExtraction != nil {
			sets = append(sets, part.TextExtraction)
		}
	}
	switch len(sets) {
	case 0:
		return nil
	case 1:
		return sets[0]
	}
	combined := TextExtraction{}
	for _, keys := range sets {
		for key := range keys {
			if _, done := combined[key]; done {
				continue
			}
			mode := ""
			for _, set := range sets {
				if own, ok := set.set(key); ok {
					mode = strongerTextExtraction(mode, own)
				}
			}
			combined[key] = mode
		}
	}
	return combined
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
