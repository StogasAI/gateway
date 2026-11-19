package policy

import "slices"

// Classifiers that the classification plugin runs on a request's text, each in constant memory
// and at a small cost for each byte, so that it suits a request and a reply of any size.
const (
	// ClassifierLanguage names the language of the newest user message and of the reply.
	ClassifierLanguage = "language"
	// ClassifierHiddenCharacters counts the input and output characters that a reader cannot see
	// and a model still reads.
	ClassifierHiddenCharacters = "hidden_characters"
)

var classifiers = []string{ClassifierHiddenCharacters, ClassifierLanguage}

// Classification returns the classifiers that the policy's plugins run, sorted. Every policy
// adds its own, so a requirement's empty list replaces only the defaults.
func (c *Config) Classification() []string {
	if c == nil {
		return nil
	}
	parts := c.PluginSources
	if len(parts) == 0 && c.Plugins != nil {
		parts = []*Plugins{c.Plugins}
	}
	return combineClassification(parts)
}

// combineClassification returns the classifiers that the parts run, sorted, an empty list when
// the parts that set the plugin run none, or nil when no part sets it.
func combineClassification(parts []*Plugins) []string {
	var names []string
	for _, part := range parts {
		if part != nil && part.Classification != nil {
			names = append(names, part.Classification...)
			if names == nil {
				names = []string{}
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func validateClassification(names []string) error {
	for i, name := range names {
		if !slices.Contains(classifiers, name) {
			return configError("unknown classifier %q", name)
		}
		if slices.Contains(names[:i], name) {
			return configError("repeated classifier %q", name)
		}
	}
	return nil
}
