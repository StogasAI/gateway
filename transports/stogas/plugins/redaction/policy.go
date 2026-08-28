package redaction

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
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

// Pattern is a stable built-in detector option. Related identifiers share one
// option so callers do not need to know the recognizer implementation.
type Pattern string

const (
	PatternEmailAddress         Pattern = "email_address"
	PatternPhoneNumber          Pattern = "phone_number"
	PatternSocialSecurityNumber Pattern = "social_security_number"
	PatternCreditCardNumber     Pattern = "credit_card_number"
	PatternIPAddress            Pattern = "ip_address"
	PatternCredentials          Pattern = "credentials"
	PatternPrivateKeys          Pattern = "private_keys"
	PatternJSONWebTokens        Pattern = "json_web_tokens"
	PatternDatabaseURLs         Pattern = "database_urls"
	PatternVendorTokens         Pattern = "vendor_tokens"
	PatternBankIdentifiers      Pattern = "bank_identifiers"
	PatternNationalIdentifiers  Pattern = "national_identifiers"
	PatternHealthIdentifiers    Pattern = "health_identifiers"
)

// Options explicitly selects built-in detector groups and custom expressions.
// An empty pattern list disables all built-in detection.
type Options struct {
	Patterns       []Pattern
	CustomPatterns []CustomPattern
}

// Policy is immutable after compilation and can be shared by concurrent
// request-local Redactors.
type Policy struct {
	entities     entityMask
	custom       *regexp.Regexp
	minimumBytes int
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
	defaultEntityMask    = allBuiltInEntityMask.without(EntityIPAddress)
	defaultPolicy        = &Policy{entities: defaultEntityMask, minimumBytes: defaultMinimumTextBytes}
)

var supportedPatterns = [...]Pattern{
	PatternEmailAddress,
	PatternPhoneNumber,
	PatternSocialSecurityNumber,
	PatternCreditCardNumber,
	PatternIPAddress,
	PatternCredentials,
	PatternPrivateKeys,
	PatternJSONWebTokens,
	PatternDatabaseURLs,
	PatternVendorTokens,
	PatternBankIdentifiers,
	PatternNationalIdentifiers,
	PatternHealthIdentifiers,
}

// CompilePolicy validates and compiles configuration once. It does not retain
// the caller's slices; the resulting policy retains only the entity mask and
// compiled matcher.
func CompilePolicy(options Options) (*Policy, error) {
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
	if custom != nil {
		minimumBytes = 1
	}
	return &Policy{entities: enabled, custom: custom, minimumBytes: minimumBytes}, nil
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
	case PatternCredentials:
		return maskOf(EntityCredential), true
	case PatternPrivateKeys:
		return maskOf(EntityPrivateKey), true
	case PatternJSONWebTokens:
		return maskOf(EntityJSONWebToken), true
	case PatternDatabaseURLs:
		return maskOf(EntityDatabaseCredential), true
	case PatternVendorTokens:
		return maskOf(EntityVendorToken), true
	case PatternBankIdentifiers:
		return maskOf(EntityIBAN, EntityUSRoutingNumber), true
	case PatternNationalIdentifiers:
		return maskOf(
			EntityUSITIN,
			EntityUKNINO,
			EntityCanadaSIN,
			EntityAustraliaTFN,
			EntityAustraliaABN,
			EntityAustraliaACN,
			EntityIndiaAadhaar,
			EntityBrazilCPF,
			EntityBrazilCNPJ,
			EntitySpainDNI,
			EntityItalyFiscalCode,
			EntityPolandPESEL,
			EntityKoreaRRN,
			EntityFinlandPersonalID,
			EntityThailandNationalID,
			EntitySingaporeNationalID,
			EntityChinaResidentID,
			EntityIsraelNationalID,
			EntitySouthAfricaID,
			EntityTurkeyNationalID,
			EntityGermanyTaxID,
			EntitySwedenPersonalID,
			EntityKoreaBusinessNumber,
			EntityItalyVAT,
			EntityNigeriaNIN,
			EntityGermanySocialSecurity,
		), true
	case PatternHealthIdentifiers:
		return maskOf(
			EntityUKNHS,
			EntityAustraliaMedicare,
			EntityUSNPI,
			EntityUSMedicareID,
			EntityGermanyHealthInsurance,
		), true
	default:
		return 0, false
	}
}

func compileCustomPatterns(patterns []CustomPattern) (*regexp.Regexp, error) {
	if len(patterns) > maxCustomPatterns {
		return nil, policyError("custom pattern count exceeds %d", maxCustomPatterns)
	}
	seen := make(map[string]struct{}, len(patterns))
	parts := make([]string, 0, len(patterns))
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
		parts = append(parts, "(?:"+expression+")")
	}
	if len(parts) == 0 {
		return nil, nil
	}
	combinedExpression := strings.Join(parts, "|")
	parsedCombined, err := syntax.Parse(combinedExpression, syntax.Perl)
	if err != nil {
		return nil, policyError("combined custom patterns cannot be parsed")
	}
	combinedProgram, err := syntax.Compile(parsedCombined.Simplify())
	if err != nil || len(combinedProgram.Inst) > maxCustomInstructions {
		return nil, policyError("combined custom patterns exceed the complexity limit")
	}
	combined, err := regexp.Compile(combinedExpression)
	if err != nil {
		return nil, policyError("combined custom patterns cannot be compiled")
	}
	combined.Longest()
	if customPatternTouchesPlaceholder(combined) {
		return nil, policyError("custom patterns can match redaction placeholders")
	}
	return combined, nil
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
