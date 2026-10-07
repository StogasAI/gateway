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
	maxCustomPatternsBytes  = 4_096
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
)

// Options explicitly selects built-in detectors and custom expressions.
// An empty pattern list disables all built-in detection.
type Options struct {
	Patterns       []Pattern
	CustomPatterns []CustomPattern
	Literals       []Literal
}

// Policy is immutable after compilation and can be shared by concurrent
// request-local Redactors.
type Policy struct {
	entities     entityMask
	custom       []*customMatcher
	minimumBytes int
	literals     []literalSelection
}

// Enabled reports whether this policy inspects provider-bound text.
func (p *Policy) Enabled() bool {
	return p != nil && (p.entities != 0 || len(p.custom) != 0 || len(p.literals) != 0)
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
	allBuiltInEntityMask = maskRange(EntityEmail, EntityDatabaseCredential)
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
	if enabled.without(EntityIPAddress) != 0 {
		minimumBytes = defaultMinimumTextBytes
	}
	if enabled.has(EntityIPAddress) && minimumBytes > 2 {
		minimumBytes = 2
	}
	if len(custom) > 0 || literals != nil {
		minimumBytes = 1
	}
	var selections []literalSelection
	if literals != nil {
		selections = []literalSelection{{matcher: literals}}
	}
	return &Policy{entities: enabled, custom: custom, minimumBytes: minimumBytes, literals: selections}, nil
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
	for _, selection := range p.literals {
		bytes += selection.matcher.bytes + int64(len(selection.enabled))
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
	totalBytes := 0
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
		totalBytes += len(expression)
		if totalBytes > maxCustomPatternsBytes {
			return nil, policyError("custom patterns exceed %d bytes", maxCustomPatternsBytes)
		}

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
	return entity >= EntityEmail && entity <= EntityDatabaseCredential && entity <= 64
}

func maxInt() int {
	return int(^uint(0) >> 1)
}

// A combined policy selects rules from shared matchers. The selection is small;
// parent dictionaries and automata remain owned by their original policies.
type literalSelection struct {
	matcher *literalMatcher
	enabled []bool
}

// CombinePolicies scans each component against the original text and merges
// intervals once. Applying redaction sequentially would lose overlapping matches.
func CombinePolicies(policies []*Policy) (*Policy, error) {
	if len(policies) == 1 {
		return policies[0], nil
	}
	out := &Policy{minimumBytes: maxInt()}
	seenCustom := map[string]bool{}
	seenMatcher := map[*literalMatcher]bool{}
	var all []Literal
	instructions := 0
	for _, p := range policies {
		if p == nil {
			continue
		}
		out.entities |= p.entities
		out.minimumBytes = min(out.minimumBytes, p.minimumBytes)
		for _, custom := range p.custom {
			if seenCustom[custom.expression] {
				continue
			}
			seenCustom[custom.expression] = true
			instructions += custom.instructions
			out.custom = append(out.custom, custom)
		}
		for _, selection := range p.literals {
			if !seenMatcher[selection.matcher] {
				seenMatcher[selection.matcher] = true
				out.literals = append(out.literals, literalSelection{matcher: selection.matcher, enabled: make([]bool, len(selection.matcher.rules))})
			}
			for i, rule := range selection.matcher.rules {
				if selection.enabled == nil || selection.enabled[i] {
					all = append(all, rule)
				}
			}
		}
	}
	if instructions > maxCustomInstructions || len(out.custom) > maxCustomPatterns {
		return nil, policyError("combined custom patterns exceed complexity limit")
	}
	normalized := NormalizeLiterals(all)
	if err := ValidateLiterals(normalized); err != nil {
		return nil, err
	}
	active := make(map[string]bool, len(normalized))
	for _, rule := range normalized {
		active[literalIdentity(rule)] = true
	}
	retained := out.literals[:0]
	for i := range out.literals {
		selection := &out.literals[i]
		selected := false
		for j, rule := range selection.matcher.rules {
			key := literalIdentity(rule)
			if active[key] {
				selection.enabled[j] = true
				selected = true
				delete(active, key)
			}
		}
		if selected {
			retained = append(retained, *selection)
		}
	}
	clear(out.literals[len(retained):])
	out.literals = retained
	return out, nil
}
