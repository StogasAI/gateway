package policy

import (
	"regexp"
	"slices"
	"strings"
	"time"

	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"

	"github.com/maximhq/bifrost/transports/stogas/location"
)

// ReasoningEfforts is the effort scale from least to most reasoning.
var ReasoningEfforts = []string{"minimal", "low", "medium", "high", "xhigh", "max"}

// fieldDomain describes the strings that a field, or an item of a list field, can hold when they
// form a closed set or have a fixed form. A comparison with any other string could never match, so
// it fails at save, and the catalog loader rejects a catalog value outside the domain.
type fieldDomain struct {
	valid func(string) bool
	hint  string
}

var (
	catalogID   = patternDomain(`^[a-z0-9][a-z0-9._:-]*$`, "a catalog ID, which uses lowercase letters, digits, '.', '_', ':' and '-'")
	catalogSlug = patternDomain(`^[a-z0-9][a-z0-9._:+-]*$`, "an alias, which uses lowercase letters, digits, '.', '_', ':', '+' and '-'")
	country     = fieldDomain{location.Country, "an uppercase ISO country code, such as 'US'"}
	catalogDate = fieldDomain{func(value string) bool {
		_, err := time.Parse(time.DateOnly, value)
		return err == nil
	}, "a date such as '2027-01-31'"}
	interfaces = oneOf("chat_completions", "responses")
	reasoning  = oneOf("unsupported", "optional", "required")
	modalities = oneOf("text", "image", "audio", "video")
	efforts    = oneOf(ReasoningEfforts...)
)

var fieldDomains = map[string]fieldDomain{
	"author.id":                   catalogID,
	"author.aliases":              catalogSlug,
	"author.headquarteredCountry": country,
	"model.id":                    catalogID,
	"model.aliases":               catalogSlug,
	"model.authorId":              catalogID,
	"model.groupIds":              catalogID,
	"model.reasoning":             reasoning,
	"model.reasoningEfforts":      efforts,
	"model.releaseDate":           catalogDate,
	"deployment.id":               catalogID,
	"deployment.modelId":          catalogID,
	"deployment.inputModalities":  modalities,
	"deployment.outputModalities": modalities,
	"deployment.reasoning":        reasoning,
	"deployment.reasoningEfforts": efforts,
	"deployment.retirementDate":   catalogDate,
	"deployment.weightPrecision":  oneOf("fp32", "bf16", "fp16", "fp8", "fp6", "fp4", "nvfp4", "mxfp4", "int8", "int4", "unknown"),
	"deployment.dataHandling.processingLocation": {func(value string) bool { return location.Valid(value, false) },
		"a location value, such as 'eu', 'world' or 'DE'"},
	"deployment.dataHandling.storageLocation": {func(value string) bool { return location.Valid(value, true) },
		"a location value, such as 'none', 'eu', 'world' or 'DE'"},
	"deployment.upstream.chuteId": patternDomain(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
		"a lowercase UUID"),
	"deployment.upstream.deploymentType": oneOf("global_standard", "data_zone_standard_us", "data_zone_standard_eu",
		"data_zone_standard_apac", "instant"),
	"deployment.upstream.hosting":       oneOf("azure", "anthropic", "fireworks"),
	"deployment.upstream.inferenceGeo":  oneOf("global", "us"),
	"deployment.upstream.modelFormat":   oneOf("OpenAI", "OpenAI-OSS", "Anthropic", "DeepSeek", "Fireworks"),
	"deployment.upstream.reasoningMode": oneOf("pro"),
	"deployment.upstream.serviceTier":   oneOf("standard", "flex", "fast", "ultrafast"),
	"route.id":                          catalogID,
	"route.providerId":                  catalogID,
	"route.interfaces":                  interfaces,
	"route.documentFormats.extensions":  patternDomain(`^\.[a-z0-9][a-z0-9._+-]*$`, "a lowercase extension with its dot, such as '.pdf'"),
	"route.documentFormats.mediaTypes":  patternDomain(`^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$`, "a lowercase media type, such as 'application/pdf'"),
	"provider.id":                       catalogID,
	"provider.aliases":                  catalogSlug,
	"provider.credentialModes":          oneOf("managed", "byok"),
	"provider.headquarteredCountry":     country,
	"request.interface":                 interfaces,
}

func oneOf(values ...string) fieldDomain {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = "'" + value + "'"
	}
	hint := quoted[len(quoted)-1]
	if len(quoted) > 1 {
		hint = strings.Join(quoted[:len(quoted)-1], ", ") + " or " + hint
	}
	return fieldDomain{func(value string) bool { return slices.Contains(values, value) }, hint}
}

func patternDomain(pattern, hint string) fieldDomain {
	return fieldDomain{regexp.MustCompile(pattern).MatchString, hint}
}

// ValidFieldValue reports whether a string can be the value of a field, or an item of a list field.
// A field without a domain, such as a name, accepts any string.
func ValidFieldValue(path, value string) bool {
	domain, ok := fieldDomains[path]
	return !ok || domain.valid(value)
}

// checkFieldLiterals rejects a string constant that the field it is compared with can never hold.
// items maps comprehension variables, as in deployment.inputModalities.exists(m, m == 'image'), to
// the list field that they iterate.
func checkFieldLiterals(checked *ast.AST, expression ast.Expr, items map[string]string) error {
	switch expression.Kind() {
	case ast.CallKind:
		call := expression.AsCall()
		args := call.Args()
		switch call.FunctionName() {
		case operators.Equals, operators.NotEquals, operators.Less, operators.LessEquals, operators.Greater, operators.GreaterEquals:
			if len(args) == 2 {
				for _, pair := range [2][2]ast.Expr{{args[0], args[1]}, {args[1], args[0]}} {
					if path, ok := fieldPath(checked, pair[0], items); ok {
						if err := checkLiterals(path, pair[1]); err != nil {
							return err
						}
					}
				}
			}
		case operators.In:
			if len(args) == 2 {
				if path, ok := fieldPath(checked, args[1], items); ok {
					if err := checkLiterals(path, args[0]); err != nil {
						return err
					}
				}
				if path, ok := fieldPath(checked, args[0], items); ok {
					if err := checkLiterals(path, args[1]); err != nil {
						return err
					}
				}
			}
		}
		if call.IsMemberFunction() {
			if err := checkFieldLiterals(checked, call.Target(), items); err != nil {
				return err
			}
		}
		for _, arg := range args {
			if err := checkFieldLiterals(checked, arg, items); err != nil {
				return err
			}
		}
	case ast.ComprehensionKind:
		comprehension := expression.AsComprehension()
		if err := checkFieldLiterals(checked, comprehension.IterRange(), items); err != nil {
			return err
		}
		if err := checkFieldLiterals(checked, comprehension.AccuInit(), items); err != nil {
			return err
		}
		scope := make(map[string]string, len(items)+1)
		for name, path := range items {
			if name != comprehension.IterVar() && name != comprehension.IterVar2() && name != comprehension.AccuVar() {
				scope[name] = path
			}
		}
		if path, ok := fieldPath(checked, comprehension.IterRange(), items); ok && !comprehension.HasIterVar2() {
			scope[comprehension.IterVar()] = path
		}
		for _, inner := range []ast.Expr{comprehension.LoopCondition(), comprehension.LoopStep(), comprehension.Result()} {
			if err := checkFieldLiterals(checked, inner, scope); err != nil {
				return err
			}
		}
	case ast.SelectKind:
		return checkFieldLiterals(checked, expression.AsSelect().Operand(), items)
	case ast.ListKind:
		for _, element := range expression.AsList().Elements() {
			if err := checkFieldLiterals(checked, element, items); err != nil {
				return err
			}
		}
	}
	return nil
}

// fieldPath names the policy field that an expression reads, or the list field that a
// comprehension variable iterates.
func fieldPath(checked *ast.AST, expression ast.Expr, items map[string]string) (string, bool) {
	switch expression.Kind() {
	case ast.IdentKind:
		path, ok := items[expression.AsIdent()]
		return path, ok
	case ast.SelectKind:
		selection := expression.AsSelect()
		parent, ok := strings.CutPrefix(checked.GetType(selection.Operand().ID()).TypeName(), celNodeTypeName(""))
		if !ok || selection.IsTestOnly() {
			return "", false
		}
		return parent + "." + selection.FieldName(), true
	}
	return "", false
}

// checkLiterals checks a string constant, or each string constant of a list literal.
func checkLiterals(path string, expression ast.Expr) error {
	domain, ok := fieldDomains[path]
	if !ok {
		return nil
	}
	values := []ast.Expr{expression}
	if expression.Kind() == ast.ListKind {
		values = expression.AsList().Elements()
	}
	for _, value := range values {
		if value.Kind() != ast.LiteralKind {
			continue
		}
		if text, ok := value.AsLiteral().(types.String); ok && !domain.valid(string(text)) {
			return configError("%s cannot be '%s'; use %s", path, text, domain.hint)
		}
	}
	return nil
}
