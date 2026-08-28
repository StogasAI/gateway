package redaction

import (
	"errors"
	"sort"
	"time"
)

const (
	maxMatchesPerText    = 65_536
	maxMatchesPerRequest = 100_000
)

var ErrMatchLimit = errors.New("PII redaction match limit exceeded")

// Entity is a high-confidence structured value that can be replaced without
// retaining the source value. The MVP deliberately excludes inferred names,
// street addresses, dates, and locations.
type Entity uint8

const (
	EntityEmail Entity = iota + 1
	EntityPhone
	EntityIPAddress
	EntityPaymentCard
	EntityIBAN
	EntityUSSSN
	EntityUSITIN
	EntityUSRoutingNumber
	EntityUKNHS
	EntityUKNINO
	EntityCanadaSIN
	EntityAustraliaTFN
	EntityAustraliaABN
	EntityAustraliaACN
	EntityAustraliaMedicare
	EntityIndiaAadhaar
	EntityBrazilCPF
	EntityBrazilCNPJ
	EntitySpainDNI
	EntityItalyFiscalCode
	EntityPolandPESEL
	EntityKoreaRRN
	EntityFinlandPersonalID
	EntityThailandNationalID
	EntitySingaporeNationalID
	EntityChinaResidentID
	EntityIsraelNationalID
	EntitySouthAfricaID
	EntityTurkeyNationalID
	EntityGermanyTaxID
	EntitySwedenPersonalID
	EntityUSNPI
	EntityKoreaBusinessNumber
	EntityItalyVAT
	EntityNigeriaNIN
	EntityUSMedicareID
	EntityGermanyHealthInsurance
	EntityGermanySocialSecurity
	EntityPrivateKey
	EntityVendorToken
	EntityJSONWebToken
	EntityCredential
	EntityDatabaseCredential
	entityCustom
)

type match struct {
	start    int
	end      int
	entity   Entity
	priority uint8
}

type Summary struct {
	ItemsRedacted uint32 `json:"items_redacted"`
	DurationUS    uint32 `json:"duration_us"`
}

// Redactor is request-local. It retains only a count and elapsed duration,
// never source values, hashes, offsets, or replacement maps.
type Redactor struct {
	policy   *Policy
	items    uint32
	duration time.Duration
}

func New() *Redactor {
	return NewWithPolicy(defaultPolicy)
}

// NewWithPolicy creates request-local state for an immutable compiled policy.
// A nil policy uses the secure default.
func NewWithPolicy(policy *Policy) *Redactor {
	if policy == nil {
		policy = defaultPolicy
	}
	return &Redactor{policy: policy}
}

func (r *Redactor) Summary() Summary {
	if r == nil {
		return Summary{}
	}
	return Summary{ItemsRedacted: r.items, DurationUS: boundedDurationMicroseconds(r.duration)}
}

func boundedDurationMicroseconds(duration time.Duration) uint32 {
	if duration <= 0 {
		return 0
	}
	microseconds := duration / time.Microsecond
	if microseconds > time.Duration(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(microseconds)
}

func (r *Redactor) redactBytes(text []byte) ([]byte, bool, error) {
	if r == nil {
		return text, false, nil
	}
	policy := r.policy
	if policy == nil {
		policy = defaultPolicy
	}
	if len(text) < policy.minimumBytes {
		return text, false, nil
	}

	var matches []match
	var err error
	if policy.entities&secretEntityMask != 0 {
		matches, err = scanSecrets(text, matches, policy.entities)
		if err != nil {
			return nil, false, err
		}
	}
	if policy.entities.has(EntityEmail) {
		matches, err = scanEmails(text, matches)
		if err != nil {
			return nil, false, err
		}
	}
	if policy.entities.has(EntityIPAddress) {
		matches, err = scanIPAddresses(text, matches)
		if err != nil {
			return nil, false, err
		}
	}
	if policy.entities&structuredNumberEntityMask != 0 {
		matches, err = scanStructuredNumbers(text, matches, policy.entities)
		if err != nil {
			return nil, false, err
		}
	}
	if policy.entities&structuredIdentifierEntityMask != 0 {
		matches, err = scanStructuredIdentifiers(text, matches, policy.entities)
		if err != nil {
			return nil, false, err
		}
	}
	if policy.custom != nil {
		matches, err = scanCustomPatterns(text, matches, policy.custom)
		if err != nil {
			return nil, false, err
		}
	}
	if len(matches) == 0 {
		return text, false, nil
	}

	matches = filterEnabledMatches(matches, policy.entities)
	matches = normalizeMatches(matches)
	if len(matches) == 0 {
		return text, false, nil
	}
	if len(matches) > maxMatchesPerText || uint64(r.items)+uint64(len(matches)) > maxMatchesPerRequest {
		return nil, false, ErrMatchLimit
	}

	outputSize := len(text)
	for _, found := range matches {
		outputSize += len(placeholder(found.entity)) - (found.end - found.start)
	}
	if outputSize < 0 {
		return nil, false, ErrMatchLimit
	}
	out := make([]byte, 0, outputSize)
	position := 0
	for _, found := range matches {
		out = append(out, text[position:found.start]...)
		out = append(out, placeholder(found.entity)...)
		position = found.end
	}
	out = append(out, text[position:]...)
	r.items += uint32(len(matches))
	return out, true, nil
}

func filterEnabledMatches(matches []match, enabled entityMask) []match {
	out := matches[:0]
	for _, candidate := range matches {
		if candidate.entity == entityCustom || enabled.has(candidate.entity) {
			out = append(out, candidate)
		}
	}
	return out
}

func appendMatch(matches []match, start, end int, entity Entity, priority uint8) ([]match, error) {
	if start < 0 || end <= start {
		return matches, nil
	}
	if len(matches) >= maxMatchesPerText {
		return nil, ErrMatchLimit
	}
	return append(matches, match{start: start, end: end, entity: entity, priority: priority}), nil
}

func normalizeMatches(matches []match) []match {
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].start != matches[j].start {
			return matches[i].start < matches[j].start
		}
		if matches[i].priority != matches[j].priority {
			return matches[i].priority > matches[j].priority
		}
		if matches[i].end != matches[j].end {
			return matches[i].end > matches[j].end
		}
		return matches[i].entity < matches[j].entity
	})

	out := matches[:0]
	for _, candidate := range matches {
		if len(out) == 0 || candidate.start >= out[len(out)-1].end {
			out = append(out, candidate)
			continue
		}
		current := &out[len(out)-1]
		// Two recognizers can cover different parts of the same sensitive value.
		// Keep the union so choosing the more specific entity never exposes the
		// lower-priority match's prefix or suffix.
		if candidate.end > current.end {
			current.end = candidate.end
		}
		if candidate.priority > current.priority {
			current.entity = candidate.entity
			current.priority = candidate.priority
		}
	}
	return out
}

func placeholder(entity Entity) string {
	switch entity {
	case EntityEmail:
		return "<EMAIL_ADDRESS>"
	case EntityPhone:
		return "<PHONE_NUMBER>"
	case EntityIPAddress:
		return "<IP_ADDRESS>"
	case EntityPaymentCard:
		return "<PAYMENT_CARD>"
	case EntityIBAN:
		return "<IBAN>"
	case EntityUSSSN:
		return "<US_SSN>"
	case EntityUSITIN:
		return "<US_ITIN>"
	case EntityUSRoutingNumber:
		return "<US_ROUTING_NUMBER>"
	case EntityUKNHS:
		return "<UK_NHS_NUMBER>"
	case EntityUKNINO:
		return "<UK_NATIONAL_INSURANCE_NUMBER>"
	case EntityCanadaSIN:
		return "<CA_SOCIAL_INSURANCE_NUMBER>"
	case EntityAustraliaTFN:
		return "<AU_TAX_FILE_NUMBER>"
	case EntityAustraliaABN:
		return "<AU_BUSINESS_NUMBER>"
	case EntityAustraliaACN:
		return "<AU_COMPANY_NUMBER>"
	case EntityAustraliaMedicare:
		return "<AU_MEDICARE_NUMBER>"
	case EntityIndiaAadhaar:
		return "<IN_AADHAAR_NUMBER>"
	case EntityBrazilCPF:
		return "<BR_CPF>"
	case EntityBrazilCNPJ:
		return "<BR_CNPJ>"
	case EntitySpainDNI:
		return "<ES_NATIONAL_ID>"
	case EntityItalyFiscalCode:
		return "<IT_FISCAL_CODE>"
	case EntityPolandPESEL:
		return "<PL_PESEL>"
	case EntityKoreaRRN:
		return "<KR_RESIDENT_NUMBER>"
	case EntityFinlandPersonalID:
		return "<FI_PERSONAL_ID>"
	case EntityThailandNationalID:
		return "<TH_NATIONAL_ID>"
	case EntitySingaporeNationalID:
		return "<SG_NATIONAL_ID>"
	case EntityChinaResidentID:
		return "<CN_RESIDENT_ID>"
	case EntityIsraelNationalID:
		return "<IL_NATIONAL_ID>"
	case EntitySouthAfricaID:
		return "<ZA_NATIONAL_ID>"
	case EntityTurkeyNationalID:
		return "<TR_NATIONAL_ID>"
	case EntityGermanyTaxID:
		return "<DE_TAX_ID>"
	case EntitySwedenPersonalID:
		return "<SE_PERSONAL_ID>"
	case EntityUSNPI:
		return "<US_NPI>"
	case EntityKoreaBusinessNumber:
		return "<KR_BUSINESS_REGISTRATION_NUMBER>"
	case EntityItalyVAT:
		return "<IT_VAT_NUMBER>"
	case EntityNigeriaNIN:
		return "<NG_NATIONAL_ID>"
	case EntityUSMedicareID:
		return "<US_MEDICARE_ID>"
	case EntityGermanyHealthInsurance:
		return "<DE_HEALTH_INSURANCE_ID>"
	case EntityGermanySocialSecurity:
		return "<DE_SOCIAL_SECURITY_NUMBER>"
	case EntityPrivateKey:
		return "<PRIVATE_KEY>"
	case EntityVendorToken:
		return "<VENDOR_TOKEN>"
	case EntityJSONWebToken:
		return "<JSON_WEB_TOKEN>"
	case EntityDatabaseCredential:
		return "<DATABASE_URL>"
	case EntityCredential:
		return "<CREDENTIAL>"
	case entityCustom:
		return "<CUSTOM_PII>"
	default:
		return "<REDACTED>"
	}
}
