package policy

import "github.com/maximhq/bifrost/transports/stogas/plugins/redaction"

func CompileRedaction(config *Config) (*redaction.Policy, error) {
	if config != nil && len(config.PluginSources) > 0 {
		parts := make([]*redaction.Policy, 0, len(config.PluginSources))
		for _, plugins := range config.PluginSources {
			part, err := CompileRedaction(&Config{Plugins: plugins})
			if err != nil {
				return nil, err
			}
			parts = append(parts, part)
		}
		return redaction.CombinePolicies(parts)
	}
	var patterns []redaction.Pattern
	var custom []redaction.CustomPattern
	var literals []redaction.Literal
	if config != nil && config.Plugins != nil && config.Plugins.StogasRedaction != nil {
		literals = config.Plugins.StogasRedaction.Literals
		for _, preset := range config.Plugins.StogasRedaction.Presets {
			patterns = append(patterns, redaction.Pattern(preset))
		}
		for _, expression := range config.Plugins.StogasRedaction.CustomPatterns {
			custom = append(custom, redaction.CustomPattern{Expression: expression})
		}
	}
	return redaction.CompilePolicy(redaction.Options{Patterns: patterns, CustomPatterns: custom, Literals: literals})
}
