package redaction

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"unicode/utf8"
)

const (
	defaultMinimumTextBytes = 6
	maxCustomPatterns       = 16
	maxCustomPatternBytes   = 512
	maxCustomInstructions   = 4_096
)

var ErrInvalidPolicy = errors.New("invalid PII redaction policy")

// CustomPattern replaces each nonempty match with <CUSTOM_PII>. Expressions
// use Go's RE2 syntax, which does not support exponential backtracking.
type CustomPattern struct {
	Expression string
}

// Pattern selects a preset of related built-in detectors.
type Pattern string

const (
	PatternEmailAddress         Pattern = "email_address"
	PatternPhoneNumber          Pattern = "phone_number"
	PatternSocialSecurityNumber Pattern = "social_security_number"
	PatternCreditCardNumber     Pattern = "credit_card_number"
	PatternIPAddress            Pattern = "ip_address"
	PatternAPIKeysAndSecrets    Pattern = "api_keys_and_secrets"
	PatternBankIdentifiers      Pattern = "bank_identifiers"
	PatternNationalIdentifiers  Pattern = "national_identifiers"
	PatternHealthIdentifiers    Pattern = "health_identifiers"
	PatternHiddenCharacters     Pattern = "hidden_characters"
)

// Part is a part of an exchange that holds text: one of the five parts of a
// request, by who wrote the text, or the response.
type Part uint8

const (
	// PartSystem is what the developer instructs: system and developer
	// messages, instructions and compaction instructions.
	PartSystem Part = iota
	// PartUser is what the user sends: user messages and a predicted output.
	PartUser
	// PartAssistant is what the model wrote earlier: assistant messages,
	// reasoning and tool calls.
	PartAssistant
	// PartToolResults is what tools returned.
	PartToolResults
	// PartTools is the tool definitions, the output format and stop sequences.
	PartTools
	// PartResponse is the response.
	PartResponse
	partCount
	// partUnknown is request text whose part the walk cannot tell, which
	// every redaction of any request part reads.
	partUnknown = partCount
)

// Parts is a set of parts.
type Parts uint8

// RequestParts is every part of a request, which a redaction reads unless it
// names its parts.
const RequestParts = Parts(1)<<PartSystem | 1<<PartUser | 1<<PartAssistant | 1<<PartToolResults | 1<<PartTools

// PartsOf returns the set of the parts.
func PartsOf(parts ...Part) Parts {
	var set Parts
	for _, part := range parts {
		set |= 1 << part
	}
	return set
}

func (p Parts) has(part Part) bool {
	if part == partUnknown {
		return p&RequestParts != 0
	}
	return p&(1<<part) != 0
}

// Action is what a redaction does with a match. Where redactions with
// different actions match the same text, refusing wins over replacing,
// replacing over restoring, and restoring over recording.
type Action uint8

const (
	// ActionReplace replaces a match with a placeholder for good.
	ActionReplace Action = iota
	// ActionRestore replaces a match with a numbered placeholder and puts
	// the value back wherever the response holds the placeholder.
	ActionRestore
	// ActionRefuse fails the request.
	ActionRefuse
	// ActionRecord counts a match and leaves the text as it is.
	ActionRecord
	actionCount
)

// Options explicitly selects built-in detectors and custom expressions.
// An empty pattern list disables all built-in detection.
type Options struct {
	Patterns       []Pattern
	CustomPatterns []CustomPattern
	Literals       []Literal
	// Parts are the parts that the detectors read, or every request part
	// when zero.
	Parts Parts
	// Action is what a match does.
	Action Action
}

// Policy is immutable after compilation and can be shared by concurrent
// request-local Redactors.
type Policy struct {
	entities     entityMask
	custom       []*customMatcher
	minimumBytes int
	// literals are the lexicons of the policies that combined, each scanned
	// by the matcher of the policy that holds it.
	literals []*literalMatcher
	// parts and action say where the detectors apply and what a match does.
	// A combination of policies that differ in either holds cells instead,
	// and its own detectors are then the union of them all.
	parts  Parts
	action Action
	cells  *policyCells
}

// policyCells holds the detectors of each part and action, with those of
// partUnknown last. Parts that the same policies read share one entry.
type policyCells struct {
	at [partCount + 1][actionCount]*Policy
	// uniform reports that every request part holds the same detectors, so
	// that a walk need not tell the parts of a request apart.
	uniform bool
}

// Enabled reports whether this policy inspects text.
func (p *Policy) Enabled() bool {
	return p != nil && (p.entities != 0 || len(p.custom) != 0 || len(p.literals) != 0)
}

// at returns the detectors that read a part with an action, or nil.
func (p *Policy) at(part Part, action Action) *Policy {
	switch {
	case !p.Enabled():
		return nil
	case p.cells != nil:
		return p.cells.at[part][action]
	case p.action == action && p.parts.has(part):
		return p
	}
	return nil
}

// uniform reports whether every part of a request holds the same detectors.
func (p *Policy) uniform() bool {
	switch {
	case !p.Enabled():
		return true
	case p.cells != nil:
		return p.cells.uniform
	}
	return p.parts&RequestParts == 0 || p.parts&RequestParts == RequestParts
}

// ChangesRequest reports whether a redaction replaces, restores or refuses matches in any part
// of a request. A redaction that only records them changes nothing.
func (p *Policy) ChangesRequest() bool {
	for action := range actionCount {
		if action != ActionRecord && p.at(partUnknown, action) != nil {
			return true
		}
	}
	return false
}

// ReadsResponse reports whether the policy reads the response.
func (p *Policy) ReadsResponse() bool {
	for action := range actionCount {
		if p.at(PartResponse, action) != nil {
			return true
		}
	}
	return false
}

// ChangesResponse reports whether a redaction replaces or refuses matches in
// the response. A redaction that only records them changes nothing.
func (p *Policy) ChangesResponse() bool {
	return p.at(PartResponse, ActionReplace) != nil || p.at(PartResponse, ActionRefuse) != nil
}

// Restores reports whether the policy replaces any request text with
// placeholders that the response gets its values back for.
func (p *Policy) Restores() bool {
	return p.at(partUnknown, ActionRestore) != nil
}

type entityMask uint64

var (
	secretEntityMask = maskOf(
		EntityPrivateKey,
		EntityVendorToken,
		EntityJSONWebToken,
		EntityCredential,
		EntityDatabaseCredential,
	)
	structuredNumberEntityMask = maskOf(
		EntityPhone,
		EntityPaymentCard,
		EntityUSSSN,
		EntityUSITIN,
		EntityUSRoutingNumber,
		EntityUKNHS,
		EntityCanadaSIN,
		EntityAustraliaTFN,
		EntityAustraliaABN,
		EntityAustraliaACN,
		EntityAustraliaMedicare,
		EntityIndiaAadhaar,
		EntityBrazilCPF,
		EntityBrazilCNPJ,
		EntityPolandPESEL,
		EntityKoreaRRN,
		EntityThailandNationalID,
		EntityIsraelNationalID,
		EntitySouthAfricaID,
		EntityTurkeyNationalID,
		EntityGermanyTaxID,
		EntitySwedenPersonalID,
		EntityUSNPI,
		EntityKoreaBusinessNumber,
		EntityItalyVAT,
		EntityNigeriaNIN,
	)
	structuredIdentifierEntityMask = maskOf(
		EntityIBAN,
		EntityUKNINO,
		EntitySpainDNI,
		EntityItalyFiscalCode,
		EntityFinlandPersonalID,
		EntitySingaporeNationalID,
		EntityChinaResidentID,
		EntityUSMedicareID,
		EntityGermanyHealthInsurance,
		EntityGermanySocialSecurity,
	)
	allBuiltInEntityMask = maskRange(EntityEmail, lastBuiltInEntity)
)

var supportedPatterns = [...]Pattern{
	PatternEmailAddress,
	PatternPhoneNumber,
	PatternSocialSecurityNumber,
	PatternCreditCardNumber,
	PatternIPAddress,
	PatternAPIKeysAndSecrets,
	PatternBankIdentifiers,
	PatternNationalIdentifiers,
	PatternHealthIdentifiers,
	PatternHiddenCharacters,
}

// CompilePolicy validates and compiles configuration once. It does not retain
// the caller's slices; the resulting policy retains only the entity mask and
// compiled matchers.
func CompilePolicy(options Options) (*Policy, error) {
	literals, err := compileLiterals(options.Literals)
	if err != nil {
		return nil, err
	}
	var enabled entityMask
	for index, pattern := range options.Patterns {
		entities, supported := entitiesForPattern(pattern)
		if !supported {
			return nil, policyError("pattern at index %d is not supported", index)
		}
		enabled |= entities
	}

	custom, err := compileCustomPatterns(options.CustomPatterns)
	if err != nil {
		return nil, err
	}
	minimumBytes := maxInt()
	if enabled.without(EntityIPAddress).without(EntityHiddenCharacters) != 0 {
		minimumBytes = defaultMinimumTextBytes
	}
	// The shortest hidden text is one tag character or two soft hyphens.
	if enabled.has(EntityHiddenCharacters) {
		minimumBytes = min(minimumBytes, 4)
	}
	if enabled.has(EntityIPAddress) {
		minimumBytes = min(minimumBytes, 2)
	}
	if len(custom) > 0 || literals != nil {
		minimumBytes = 1
	}
	var matchers []*literalMatcher
	if literals != nil {
		matchers = []*literalMatcher{literals}
	}
	parts, action := options.Parts, options.Action
	if parts == 0 {
		parts = RequestParts
	}
	if parts >= 1<<partCount || action >= actionCount {
		return nil, policyError("parts or action is not supported")
	}
	if action == ActionRestore && parts.has(PartResponse) {
		return nil, policyError("a redaction that restores values cannot read the response")
	}
	return &Policy{entities: enabled, custom: custom, minimumBytes: minimumBytes, literals: matchers, parts: parts, action: action}, nil
}

// MemoryBytes conservatively accounts for retained matcher allocations, not
// process RSS. Compile callers separately bound concurrency and transient work.
func (p *Policy) MemoryBytes() int64 {
	if p == nil {
		return 0
	}
	bytes := int64(4096)
	for _, matcher := range p.custom {
		bytes += matcher.memoryBytes
	}
	for _, matcher := range p.literals {
		bytes += matcher.bytes
	}
	return bytes
}

func entitiesForPattern(pattern Pattern) (entityMask, bool) {
	switch pattern {
	case PatternEmailAddress:
		return maskOf(EntityEmail), true
	case PatternPhoneNumber:
		return maskOf(EntityPhone), true
	case PatternSocialSecurityNumber:
		return maskOf(EntityUSSSN), true
	case PatternCreditCardNumber:
		return maskOf(EntityPaymentCard), true
	case PatternIPAddress:
		return maskOf(EntityIPAddress), true
	case PatternAPIKeysAndSecrets:
		return secretEntityMask, true
	case PatternBankIdentifiers:
		return maskOf(EntityIBAN, EntityUSRoutingNumber), true
	case PatternNationalIdentifiers:
		return maskOf(
			EntityUSITIN, EntityUKNINO, EntityCanadaSIN,
			EntityAustraliaTFN, EntityAustraliaABN, EntityAustraliaACN,
			EntityIndiaAadhaar, EntityBrazilCPF, EntityBrazilCNPJ,
			EntitySpainDNI, EntityItalyFiscalCode, EntityPolandPESEL,
			EntityKoreaRRN, EntityFinlandPersonalID, EntityThailandNationalID,
			EntitySingaporeNationalID, EntityChinaResidentID, EntityIsraelNationalID,
			EntitySouthAfricaID, EntityTurkeyNationalID, EntityGermanyTaxID,
			EntitySwedenPersonalID, EntityKoreaBusinessNumber, EntityItalyVAT,
			EntityNigeriaNIN, EntityGermanySocialSecurity,
		), true
	case PatternHealthIdentifiers:
		return maskOf(EntityUKNHS, EntityAustraliaMedicare, EntityUSNPI,
			EntityUSMedicareID, EntityGermanyHealthInsurance), true
	case PatternHiddenCharacters:
		return maskOf(EntityHiddenCharacters), true
	default:
		return 0, false
	}
}

// ValidateCustomPatterns uses the same compiler as request execution without
// constructing a literal matcher. Policy editors use it before saving rules.
func ValidateCustomPatterns(patterns []CustomPattern) error {
	_, err := compileCustomPatterns(patterns)
	return err
}

func compileCustomPatterns(patterns []CustomPattern) ([]*customMatcher, error) {
	if len(patterns) > maxCustomPatterns {
		return nil, policyError("custom pattern count exceeds %d", maxCustomPatterns)
	}
	seen := make(map[string]struct{}, len(patterns))
	compiled := make([]*customMatcher, 0, len(patterns))
	totalInstructions := 0
	for index, pattern := range patterns {
		expression := pattern.Expression
		if expression == "" {
			return nil, policyError("custom pattern %d is empty", index)
		}
		if !utf8.ValidString(expression) {
			return nil, policyError("custom pattern %d is not valid UTF-8", index)
		}
		if len(expression) > maxCustomPatternBytes {
			return nil, policyError("custom pattern %d exceeds %d bytes", index, maxCustomPatternBytes)
		}
		if _, duplicate := seen[expression]; duplicate {
			continue
		}
		seen[expression] = struct{}{}

		parsed, parseErr := syntax.Parse(expression, syntax.Perl)
		if parseErr != nil {
			return nil, policyError("custom pattern %d has invalid syntax", index)
		}
		parsed = parsed.Simplify()
		if minimumRegexpRunes(parsed) == 0 {
			return nil, policyError("custom pattern %d can match without consuming text", index)
		}
		program, compileErr := syntax.Compile(parsed)
		if compileErr != nil {
			return nil, policyError("custom pattern %d cannot be compiled", index)
		}
		totalInstructions += len(program.Inst)
		if totalInstructions > maxCustomInstructions {
			return nil, policyError("custom patterns exceed the complexity limit")
		}
		matcher, err := regexp.Compile(expression)
		if err != nil {
			return nil, policyError("custom pattern %d cannot be compiled", index)
		}
		matcher.Longest()
		if customPatternTouchesPlaceholder(matcher) {
			return nil, policyError("custom patterns can match redaction placeholders")
		}
		compiled = append(compiled, newCustomMatcher(expression, program))
	}
	return compiled, nil
}

func minimumRegexpRunes(expression *syntax.Regexp) int {
	switch expression.Op {
	case syntax.OpLiteral:
		return len(expression.Rune)
	case syntax.OpCharClass, syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return 1
	case syntax.OpCapture, syntax.OpPlus:
		return minimumRegexpRunes(expression.Sub[0])
	case syntax.OpConcat:
		minimum := 0
		for _, child := range expression.Sub {
			minimum += minimumRegexpRunes(child)
		}
		return minimum
	case syntax.OpAlternate:
		minimum := maxInt()
		for _, child := range expression.Sub {
			if childMinimum := minimumRegexpRunes(child); childMinimum < minimum {
				minimum = childMinimum
			}
		}
		return minimum
	case syntax.OpRepeat:
		return expression.Min * minimumRegexpRunes(expression.Sub[0])
	default:
		return 0
	}
}

func policyError(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPolicy, fmt.Sprintf(format, arguments...))
}

func (m entityMask) has(entity Entity) bool {
	if !builtInEntity(entity) {
		return false
	}
	return m&(entityMask(1)<<uint(entity-1)) != 0
}

func (m entityMask) with(entity Entity) entityMask {
	if !builtInEntity(entity) {
		return m
	}
	return m | entityMask(1)<<uint(entity-1)
}

func (m entityMask) without(entity Entity) entityMask {
	if !builtInEntity(entity) {
		return m
	}
	return m &^ (entityMask(1) << uint(entity-1))
}

func maskOf(entities ...Entity) entityMask {
	var result entityMask
	for _, entity := range entities {
		result = result.with(entity)
	}
	return result
}

func maskRange(first, last Entity) entityMask {
	var result entityMask
	for entity := first; entity <= last; entity++ {
		result = result.with(entity)
	}
	return result
}

func builtInEntity(entity Entity) bool {
	return entity >= EntityEmail && entity <= lastBuiltInEntity && entity <= 64
}

func maxInt() int {
	return int(^uint(0) >> 1)
}

// CombinePolicies scans each component against the original text and merges
// intervals once. Applying redaction sequentially would lose overlapping matches.
// The combination has no bound of its own: each policy passed its bounds when
// it compiled, and every scan charges the request's work, so no policy can
// make another's fail to combine. It shares the components' matchers and reads
// none of their rules, so combining costs the same whatever they hold.
//
// Each part and action gets the detectors of the components that read that
// part with that action, so adding a component only ever makes the handling
// of a text stricter.
func CombinePolicies(policies []*Policy) (*Policy, error) {
	enabled := make([]*Policy, 0, len(policies))
	same := true
	for _, p := range policies {
		if !p.Enabled() {
			continue
		}
		enabled = append(enabled, p)
		same = same && p.cells == nil && p.parts == enabled[0].parts && p.action == enabled[0].action
	}
	if len(policies) == 1 {
		return policies[0], nil
	}
	out := unionOf(enabled)
	if len(enabled) == 0 {
		return out, nil
	}
	if same {
		out.parts, out.action = enabled[0].parts, enabled[0].action
		return out, nil
	}
	cells := &policyCells{uniform: true}
	shared := map[string]*Policy{}
	for part := range Part(partCount + 1) {
		for action := range actionCount {
			var members []*Policy
			key := make([]byte, 0, 8*len(enabled))
			for _, p := range enabled {
				if member := p.at(part, action); member != nil {
					members = append(members, member)
					key = fmt.Appendf(key, "%p,", member)
				}
			}
			if len(members) == 0 {
				continue
			}
			cell, ok := shared[string(key)]
			if !ok {
				cell = unionOf(members)
				// A cell is read through the combination, never as a policy of its own.
				cell.parts, cell.action = PartsOf(part), action
				shared[string(key)] = cell
			}
			cells.at[part][action] = cell
		}
	}
	for part := PartSystem; part < PartResponse; part++ {
		if cells.at[part] != cells.at[PartSystem] {
			cells.uniform = false
		}
	}
	out.cells = cells
	return out, nil
}

// unionOf returns the detectors of every policy together.
func unionOf(policies []*Policy) *Policy {
	out := &Policy{minimumBytes: maxInt()}
	seenCustom := map[string]bool{}
	seenMatcher := map[*literalMatcher]bool{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		out.entities |= p.entities
		out.minimumBytes = min(out.minimumBytes, p.minimumBytes)
		for _, custom := range p.custom {
			if !seenCustom[custom.expression] {
				seenCustom[custom.expression] = true
				out.custom = append(out.custom, custom)
			}
		}
		for _, matcher := range p.literals {
			if !seenMatcher[matcher] {
				seenMatcher[matcher] = true
				out.literals = append(out.literals, matcher)
			}
		}
	}
	return out
}
