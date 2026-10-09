package policy

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
)

// Permission is a set of policy sections. Groups and their children resolve to
// the same bits, so composition is an intersection with no ordering priority.
type Permission uint16

const (
	permissionAccess Permission = 1 << iota
	permissionInput
	permissionLimits
	permissionPlugins
	permissionEncryptedPlugins
	permissionFilter
	permissionSort
	permissionNodes
	permissionAttempts
	permissionDelegation
	permissionTextExtraction
	permissionEncryption
	permissionExport
	permissionTotalTimeout
	permissionOutputIdleTimeout
	permissionSelection
	allPermissions     = permissionSelection | (permissionSelection - 1)
	requestPermissions = allPermissions &^ (permissionLimits | permissionDelegation | permissionEncryption)
)

var permissionSections = map[string]Permission{
	"access": permissionAccess, "input": permissionInput, "limits": permissionLimits,
	"timeouts":                     permissionTotalTimeout | permissionOutputIdleTimeout,
	"timeouts.totalSeconds":        permissionTotalTimeout,
	"timeouts.outputIdleSeconds":   permissionOutputIdleTimeout,
	"plugins":                      permissionPlugins | permissionEncryptedPlugins | permissionTextExtraction | permissionExport,
	"plugins.stogasExport":         permissionExport,
	"plugins.stogasTextExtraction": permissionTextExtraction,
	"plugins.stogasRedaction":      permissionPlugins, "plugins.encrypted": permissionEncryptedPlugins,
	"routing":        permissionFilter | permissionSort | permissionNodes | permissionAttempts | permissionSelection,
	"routing.filter": permissionFilter, "routing.sort": permissionSort,
	"routing.allowedCatalogNodes": permissionNodes, "routing.maxAttempts": permissionAttempts,
	"routing.selection": permissionSelection,
	"delegation":        permissionDelegation, "encryption": permissionEncryption,
}

var policyEntityID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func (p *Permission) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("true")) {
		*p = allPermissions
		return nil
	}
	if bytes.Equal(raw, []byte("false")) {
		*p = 0
		return nil
	}
	var sections []string
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &sections) != nil {
		return configError("policy permissions must be a boolean or a list of sections")
	}
	var result Permission
	seen := make(map[string]bool, len(sections))
	for _, section := range sections {
		value, ok := permissionSections[section]
		if !ok || seen[section] {
			return configError("invalid or repeated policy section %q", section)
		}
		seen[section] = true
		result |= value
	}
	*p = result
	return nil
}

func (p Permission) MarshalJSON() ([]byte, error) {
	if p == 0 {
		return []byte("false"), nil
	}
	if p == allPermissions {
		return []byte("true"), nil
	}
	sections := make([]string, 0, len(permissionSections))
	for section, mask := range permissionSections {
		if section == "routing" || section == "plugins" || section == "timeouts" {
			continue
		}
		if p&mask == mask {
			sections = append(sections, section)
		}
	}
	sort.Strings(sections)
	return json.Marshal(sections)
}

type DelegationRule struct {
	Default    Permission            `json:"default"`
	Exceptions map[string]Permission `json:"exceptions"`
}

func (r *DelegationRule) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return configError("invalid policy delegation")
	}
	if raw[0] != '{' {
		return json.Unmarshal(raw, &r.Default)
	}
	var rule struct {
		Default    *Permission           `json:"default"`
		Exceptions map[string]Permission `json:"exceptions"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&rule) != nil || rule.Default == nil || len(rule.Exceptions) == 0 {
		return configError("delegation requires a default and named ID exceptions")
	}
	for id := range rule.Exceptions {
		if !policyEntityID.MatchString(id) {
			return configError("delegation exceptions require lowercase UUIDv7 IDs")
		}
	}
	r.Default, r.Exceptions = *rule.Default, rule.Exceptions
	return nil
}

type RequestPermission Permission

func (p *RequestPermission) UnmarshalJSON(raw []byte) error {
	var value Permission
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		value = requestPermissions
	}
	if value&^requestPermissions != 0 {
		return configError("request permissions cannot allow limits, delegation, or encryption settings")
	}
	*p = RequestPermission(value)
	return nil
}

func (p RequestPermission) MarshalJSON() ([]byte, error) {
	if Permission(p) == requestPermissions {
		return []byte("true"), nil
	}
	return json.Marshal(Permission(p))
}

func (r *DelegationRule) Permission(id string) Permission {
	if r == nil {
		return allPermissions
	}
	if value, ok := r.Exceptions[id]; id != "" && ok {
		return value
	}
	return r.Default
}

// Saved-policy delegation follows resource ownership. Membership and credential
// assignments determine which restrictions apply, but never transfer ownership
// of policies belonging to resources elsewhere in the organization.
type Delegation struct {
	Folders     *DelegationRule    `json:"folders"`
	Grants      *DelegationRule    `json:"grants"`
	Roles       *DelegationRule    `json:"roles"`
	Members     *DelegationRule    `json:"members"`
	Credentials *DelegationRule    `json:"credentials"`
	Keys        *DelegationRule    `json:"keys"`
	Request     *RequestPermission `json:"request"`
}

func (d *Delegation) saved() map[Scope]*DelegationRule {
	if d == nil {
		return nil
	}
	return map[Scope]*DelegationRule{
		FolderScope: d.Folders, GrantScope: d.Grants, RoleScope: d.Roles,
		MemberScope: d.Members, CredentialScope: d.Credentials, KeyScope: d.Keys,
	}
}

func (d *Delegation) validateScope(scope Scope) error {
	for target, rule := range d.saved() {
		if rule == nil {
			continue
		}
		if scope != OrganizationScope &&
			!(scope == FolderScope && (target == GrantScope || target == KeyScope)) &&
			!(scope == GrantScope && target == KeyScope) {
			return configError("%s policies cannot delegate %s policy edits", scope, target)
		}
	}
	return nil
}

func (d *SourceDocument) sections() Permission {
	sections := d.ownSections()
	for _, rule := range d.rules {
		sections |= rule.source.usedSections
	}
	return sections
}

func (d *SourceDocument) ownSections() Permission {
	var sections Permission
	for name, raw := range d.fields {
		if name == "plugins" && d.Encrypted() {
			sections |= permissionEncryptedPlugins
			continue
		}
		if name == "routing" || name == "plugins" || name == "timeouts" {
			var settings map[string]json.RawMessage
			if json.Unmarshal(raw, &settings) == nil {
				for option := range settings {
					sections |= permissionSections[name+"."+option]
				}
			}
		} else {
			sections |= permissionSections[name]
		}
	}
	return sections
}
