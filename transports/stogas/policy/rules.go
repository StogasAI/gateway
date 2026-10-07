package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"sort"
)

// Rules are unordered, named settings. Names identify conditional counters;
// neither a rule's name nor its position gives its settings precedence.
type Rule struct {
	Name         string
	When         *CELExpression
	Default      bool
	Value        *Source
	Encrypted    *SourceDocument
	HasLimits    bool
	previewBytes int
}

type RuleMatch struct {
	Source int
	Name   string
}

var ErrUnknownCondition = errors.New("policy condition requires a catalog fact that is unavailable")

type ruleDocument struct {
	fields map[string]json.RawMessage
	source *SourceDocument
	bytes  int
}

func parseRuleDocuments(raw json.RawMessage, envelopes map[[32]byte]encryptedPlugin) (map[string]ruleDocument, error) {
	if raw == nil {
		return nil, nil
	}
	var entries map[string]json.RawMessage
	if jsonv2.Unmarshal(raw, &entries) != nil || entries == nil || len(entries) == 0 {
		return nil, configError("rules require a nonempty object")
	}
	documents := make(map[string]ruleDocument, len(entries))
	for name, entry := range entries {
		if !policyName.MatchString(name) || name == "constructor" || name == "prototype" {
			return nil, configError("rule names require lowercase letters, digits, underscores or hyphens, starting with a letter")
		}
		var fields map[string]json.RawMessage
		if jsonv2.Unmarshal(entry, &fields) != nil || fields == nil {
			return nil, configError("rule %q requires an object", name)
		}
		settings := make(map[string]json.RawMessage, len(fields))
		for field, value := range fields {
			switch field {
			case "when", "mode":
			case "limits", "routing", "plugins", "input", "access":
				settings[field] = value
			default:
				return nil, configError("unknown rule field %q", field)
			}
		}
		if len(settings) == 0 {
			return nil, configError("rule %q requires at least one setting", name)
		}
		document, err := sourceDocument(canonicalSourceFields(settings), settings, envelopes)
		if err != nil {
			return nil, err
		}
		documents[name] = ruleDocument{fields: fields, source: document, bytes: len(entry) + len(name) - document.envelopeBytes}
	}
	return documents, nil
}

func compileRules(documents map[string]ruleDocument, plugins map[[32]byte]*Plugins, compiler *celCompiler) ([]Rule, error) {
	names := make([]string, 0, len(documents))
	for name := range documents {
		names = append(names, name)
	}
	sort.Strings(names)
	rules := make([]Rule, 0, len(names))
	for _, name := range names {
		document := documents[name]
		fields := document.fields
		rule := Rule{Name: name}
		if value, ok := fields["mode"]; ok {
			var mode string
			if json.Unmarshal(value, &mode) != nil || mode != "default" && mode != "required" {
				return nil, configError("rule mode must be required or default")
			}
			rule.Default = mode == "default"
		}
		if value, ok := fields["when"]; ok {
			var condition string
			if json.Unmarshal(value, &condition) != nil || condition == "" {
				return nil, configError("rule when requires a CEL condition")
			}
			var err error
			rule.When, err = compiler.compile(condition, true)
			if err != nil {
				return nil, err
			}
		}
		rule.HasLimits = fields["limits"] != nil
		if rule.Default && rule.HasLimits {
			return nil, configError("shared limits must be required")
		}
		var err error
		rule.Value, err = document.source.compile(plugins, compiler)
		if err != nil {
			return nil, err
		}
		if document.source.Encrypted() {
			// Its condition and readable settings can be evaluated without the
			// root. Open only the active, selected request's encrypted plugins.
			rule.Encrypted = document.source
		}
		rule.previewBytes = document.bytes
		rules = append(rules, rule)
	}
	return rules, nil
}

// ConditionDigest separates counter populations after a condition edit while
// retaining their identity across whitespace and equivalent CEL formatting.
func (r Rule) ConditionDigest() string {
	condition := "true"
	if r.When != nil {
		condition = r.When.normalized
		if condition == "" {
			condition = r.When.Source
		}
	}
	digest := sha256.Sum256([]byte(condition))
	return hex.EncodeToString(digest[:])
}

// Activate resolves one candidate's rules before redaction or token counting.
// A request budget is shared with filters and sorting through Values. The
// returned configuration belongs to this request; cached sources stay immutable.
func (c *Config) Activate(values Values) (*Config, error) {
	if c == nil || !c.hasRules {
		return c, nil
	}
	active := append([]ScopedSource{}, c.sources...)
	var matches []RuleMatch
	var opaque []*SourceDocument
	for index, entry := range c.sources {
		for _, rule := range entry.Value.Rules {
			if rule.When == nil {
				if bounded, ok := values.(interface{ PolicyCELBudget() *CELBudget }); ok {
					if budget := bounded.PolicyCELBudget(); budget != nil {
						if budget.remaining == 0 {
							return nil, ErrPolicyWorkLimit
						}
						budget.remaining--
					}
				}
			}
			if rule.When != nil {
				known, matched, _, err := rule.When.Evaluate(values, policyTime(values))
				if err != nil {
					return nil, err
				}
				if !known {
					return nil, ErrUnknownCondition
				}
				if !matched {
					continue
				}
			}
			part := *rule.Value
			part.defaultSettings = rule.Default
			part.encryptedPlugins = rule.Encrypted
			active = append(active, ScopedSource{Scope: entry.Scope, Value: &part})
			if rule.HasLimits {
				matches = append(matches, RuleMatch{Source: index, Name: rule.Name})
			}
		}
	}
	out, err := composeSettings(active)
	if err != nil {
		return nil, err
	}
	for _, entry := range active {
		if entry.Value.encryptedPlugins != nil && (!entry.Value.defaultSettings || out.requiredSettings&pluginPermissions == 0) {
			opaque = append(opaque, entry.Value.encryptedPlugins)
		}
	}
	out.ActiveRules, out.ActiveEncryptedPlugins = matches, opaque
	out.activated = true
	return out, nil
}

const pluginPermissions = permissionPlugins | permissionEncryptedPlugins | permissionTextExtraction | permissionExport

// HasRequiredSort includes an explicit empty ordering, which suppresses
// defaults without removing any other applicable required ordering.
func (c *Config) HasRequiredSort() bool {
	return c != nil && c.requiredSettings&permissionSort != 0
}

func settingsMask(value Permission) Permission {
	if value&pluginPermissions != 0 {
		value |= pluginPermissions
	}
	return value & requestPermissions
}

// ExpressionBytes charges every immutable program once per source.
func (s *Source) ExpressionBytes() int64 {
	if s == nil {
		return 0
	}
	seen := make(map[*CELExpression]bool)
	var total int64
	add := func(expression *CELExpression) {
		if expression != nil && !seen[expression] {
			seen[expression] = true
			total += expression.bytes
		}
	}
	s.Config.visitExpressions(add)
	for _, rule := range s.Rules {
		add(rule.When)
		rule.Value.Config.visitExpressions(add)
	}
	return total
}
