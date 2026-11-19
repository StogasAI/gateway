package policy

import (
	"errors"
	"strings"

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

// SectionsError says which bound of one policy its plugin sections pass
// together and, in a request, names the policy. The reason holds counts and
// no setting, so it is safe to show for encrypted plugins too.
type SectionsError struct {
	Origin Origin
	Scope  Scope
	err    error
}

func (e *SectionsError) Error() string { return e.err.Error() }
func (e *SectionsError) Unwrap() error { return e.err }

// Reason says which bound the policy passed, without the error's prefix.
func (e *SectionsError) Reason() string {
	return strings.TrimPrefix(e.err.Error(), ErrInvalidConfig.Error()+": ")
}

// CheckSections bounds what the plugin sections of one policy hold together:
// its own plugins and those of its rules, which one request can match at
// once. The policies of a request combine without a bound of their own, so
// these bounds are what keeps one request's matchers and deliveries finite:
// exportconfig.MaxDestinations destinations, redaction.MaxLiterals literal
// rules in redaction.MaxLiteralTotalBytes, and the custom patterns that one
// redaction policy compiles. Each section passed the same bounds alone.
func CheckSections(sections []*Plugins) error {
	seen := make(map[*Plugins]bool, len(sections))
	var exports []*exportconfig.Config
	var literals []redaction.Literal
	patterns := map[string]bool{}
	for _, plugins := range sections {
		if plugins == nil || seen[plugins] {
			continue
		}
		seen[plugins] = true
		if plugins.Export != nil {
			exports = append(exports, plugins.Export)
		}
		if plugins.Redaction != nil {
			literals = append(literals, plugins.Redaction.Literals...)
			for _, pattern := range plugins.Redaction.CustomPatterns {
				patterns[pattern] = true
			}
		}
	}
	if len(exports) > 1 {
		combined, err := exportconfig.Combine(exports...)
		if err != nil {
			return err
		}
		if len(combined.Destinations) > exportconfig.MaxDestinations {
			return &SectionsError{err: configError("a policy exports to at most %d destinations, counting its rules", exportconfig.MaxDestinations)}
		}
	}
	if redaction.ValidateLiterals(literals) != nil {
		return &SectionsError{err: configError("a policy holds at most %d redaction literals in %d bytes, counting its rules", redaction.MaxLiterals, redaction.MaxLiteralTotalBytes)}
	}
	// One pattern compiled with its own section.
	if len(patterns) > 1 {
		custom := make([]redaction.CustomPattern, 0, len(patterns))
		for pattern := range patterns {
			custom = append(custom, redaction.CustomPattern{Expression: pattern})
		}
		if redaction.ValidateCustomPatterns(custom) != nil {
			return &SectionsError{err: configError("the custom patterns of a policy and its rules exceed the count or complexity of one policy")}
		}
	}
	return nil
}

// checkSections bounds a policy with its rules when it compiles.
func (s *Source) checkSections() error {
	if len(s.Rules) == 0 {
		return nil
	}
	sections := make([]*Plugins, 0, 1+len(s.Rules))
	sections = append(sections, s.Config.Plugins)
	for _, rule := range s.Rules {
		sections = append(sections, rule.Value.Config.Plugins)
	}
	return CheckSections(sections)
}

// WithOpened returns c with the opened plugins of its ActiveEncryptedPlugins,
// in their order, among its plugin sections. Only a gateway reads what an
// encrypted plugin holds, so each policy that opened one is bounded here with
// its other sections that apply.
func (c *Config) WithOpened(opened []*Plugins) (*Config, error) {
	out := *c
	out.PluginSources = append([]*Plugins{}, c.PluginSources...)
	out.pluginPolicies = append([]int{}, c.pluginPolicies...)
	if len(out.PluginSources) != len(out.pluginPolicies) {
		// A configuration that no chain composed is one policy.
		out.pluginPolicies = make([]int, len(out.PluginSources))
	}
	if len(out.PluginSources) == 0 && c.Plugins != nil {
		out.PluginSources, out.pluginPolicies = []*Plugins{c.Plugins}, []int{0}
	}
	checked := map[int]bool{}
	for i, plugins := range opened {
		position := c.ActiveEncryptedPlugins[i].policy
		out.PluginSources = append(out.PluginSources, plugins)
		out.pluginPolicies = append(out.pluginPolicies, position)
		checked[position] = false
	}
	for i, position := range out.pluginPolicies {
		if done, opened := checked[position]; done || !opened {
			continue
		}
		checked[position] = true
		var sections []*Plugins
		for j := i; j < len(out.PluginSources); j++ {
			if out.pluginPolicies[j] == position {
				sections = append(sections, out.PluginSources[j])
			}
		}
		if err := CheckSections(sections); err != nil {
			if failed := (*SectionsError)(nil); errors.As(err, &failed) && position < len(c.sources) {
				failed.Origin, failed.Scope = Origin{Source: position}, c.sources[position].Scope
			}
			return nil, err
		}
	}
	return &out, nil
}
