package redaction

import (
	"bytes"
	"errors"
	"sort"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/plugins/classification"
)

const (
	maxMatchesPerText    = 65_536
	maxMatchesPerRequest = 100_000
	// Meter variable lookahead, including repeat reads, across the request.
	// Units account for matcher complexity; they are not CPU milliseconds.
	maxScanWork = 64 * 1024 * 1024
)

var ErrMatchLimit = errors.New("PII redaction match limit exceeded")
var ErrWorkLimit = errors.New("redaction work limit exceeded")
var ErrNonASCII = errors.New("input text must contain only ASCII characters")

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
	EntityHiddenCharacters
	entityCustom
	// lastBuiltInEntity is the last entity that a built-in detector finds.
	lastBuiltInEntity = entityCustom - 1
)

type match struct {
	start    int
	end      int
	entity   Entity
	priority uint8
	// restore marks a match that only restoring detectors found.
	restore bool
}

// Summary counts what one walk replaced. ItemsRestored counts the placeholders of a response
// that got their values back, and ItemsRecorded the matches of recording redactions that stayed
// as they were.
type Summary struct {
	ItemsRedacted uint32 `json:"items_redacted"`
	ItemsRestored uint32 `json:"items_restored,omitempty"`
	ItemsRecorded uint32 `json:"items_recorded,omitempty"`
	DurationUS    uint32 `json:"duration_us"`
}

// RefusedError reports text that a refusing redaction matched. It names the kind of value and
// never the value.
type RefusedError struct {
	Entity Entity
}

func (e *RefusedError) Error() string {
	return "text holds a value that a redaction refuses: " + placeholder(e.Entity)
}

// Placeholder names the kind of value that the redaction refused, as its placeholder.
func (e *RefusedError) Placeholder() string { return placeholder(e.Entity) }

// Redactor is local to one request or one response. It retains counts and elapsed duration,
// and never hashes or offsets. The values that restoring redactions replaced stay in it, and
// in the Restorer that it gives, for as long as the request runs.
type Redactor struct {
	policy *Policy
	// part is the part of the exchange that the walk reads.
	part  Part
	items uint32
	// recorded counts the matches of recording redactions that no other redaction changed.
	recorded uint32
	// piece is set while a reply's walk reads a piece of a text that goes on. A match can span
	// two pieces, so recording waits for the whole text (RecordReplyText).
	piece bool
	// restorer numbers the values that restoring redactions replace in a request. values holds
	// those of the request that a response answers, and restored counts the ones it put back.
	restorer *Restorer
	values   *Restorer
	restored uint32
	// reply marks the walk of a response, and argumentsJSON a string that holds a JSON document,
	// where a restored value must stay inside its JSON string.
	reply         bool
	argumentsJSON bool
	// jsonOutput marks a reply whose text is a JSON document, because its request asked for
	// JSON output.
	jsonOutput bool
	// messages marks the walk of Claude's own reply to a Messages request.
	messages bool
	// keepPlaceholders is set while a reply's walk reads reasoning, which gets no value back.
	keepPlaceholders bool
	// input measures the provider-bound text that the walk passes, after redaction.
	input            inputText
	countHidden      bool
	duration         time.Duration
	scanWork         uint64
	asciiOnly        bool
	expansion        int
	reserveExpansion func(int) error
	// sealedDetails counts the signed or encrypted reasoning details that the walk has passed, so
	// that a message knows whether it holds one.
	sealedDetails int
	// searchResults are the encrypted search results that the walk has passed in the current
	// Responses input item.
	searchResults []jsonSpan
}

// NewWithPolicy creates request-local state for an immutable compiled policy.
// A nil policy leaves text unchanged.
func NewWithPolicy(policy *Policy) *Redactor {
	return &Redactor{policy: policy, part: partUnknown}
}

// NewReply creates the state that redacts one response: the policy's detectors for the
// response, and the values that the request's restoring redactions replaced. It returns nil
// when neither changes a response.
func NewReply(policy *Policy, values *Restorer) *Redactor {
	if !policy.ReadsResponse() && values == nil {
		return nil
	}
	return &Redactor{policy: policy, part: PartResponse, reply: true, values: values}
}

// JSONOutput marks a reply whose text is a JSON document, because its request asked for JSON
// output. A value that the reply gets back is then written as the inside of a JSON string, as in
// a tool call's arguments, so a value that holds a quote or a line break leaves the document valid.
func (r *Redactor) JSONOutput() {
	if r != nil {
		r.jsonOutput = true
	}
}

// ChangesResponse reports whether a redaction of the response's own replaces or refuses its
// matches. Such a reply is changed whole, and one that only gets values back is changed as its
// text arrives.
func (r *Redactor) ChangesResponse() bool {
	return r != nil && r.policy.ChangesResponse()
}

// RecordsResponse reports whether a redaction records the matches of the response.
func (r *Redactor) RecordsResponse() bool {
	return r != nil && r.policy.at(PartResponse, ActionRecord) != nil
}

// Restorer returns the values that the walk replaced with numbered placeholders, or nil when
// it replaced none.
func (r *Redactor) Restorer() *Restorer {
	if r == nil || r.restorer == nil || len(r.restorer.values) == 0 {
		return nil
	}
	return r.restorer
}

// Summary is absent when no redaction rules were applied. A configured scan
// retains its metrics even when it finds no matches.
func (r *Redactor) Summary() *Summary {
	if r == nil || !r.policy.Enabled() && r.values == nil {
		return nil
	}
	return &Summary{ItemsRedacted: r.items, ItemsRestored: r.restored, ItemsRecorded: r.recorded, DurationUS: boundedDurationMicroseconds(r.duration)}
}

// InputTextBytes counts decoded UTF-8 text after transformation. It uses the
// same request text traversal even when redaction is disabled, excluding
// protocol identifiers and protected reasoning replay.
func (r *Redactor) InputTextBytes() int {
	if r == nil {
		return 0
	}
	return r.input.bytes
}

// CountHidden has the walk also count the hidden characters of the text that
// InputTextBytes measures, as the request holds it before redaction
// (classification.Hidden), so that a redaction of them does not hide them.
func (r *Redactor) CountHidden() {
	r.countHidden = true
}

// HiddenCharacters is the count that CountHidden asked for.
func (r *Redactor) HiddenCharacters() int {
	if r == nil {
		return 0
	}
	return r.input.hidden
}

// inputText is what the walk measures of the text that it passes.
type inputText struct {
	bytes, hidden int
}

func (t inputText) minus(other inputText) inputText {
	return inputText{bytes: t.bytes - other.bytes, hidden: t.hidden - other.hidden}
}

// measure measures a text that redaction changed from original.
func (r *Redactor) measure(original, text []byte) {
	r.input.bytes += len(text)
	if r.countHidden {
		r.input.hidden += classification.CountHidden(original)
	}
}

func (r *Redactor) chargeScanWork(amount uint64) bool {
	if amount > maxScanWork-r.scanWork {
		r.scanWork = maxScanWork
		return false
	}
	r.scanWork += amount
	return true
}

func (r *Redactor) reserveGrowth(bytes int) error {
	if bytes <= 0 || r.reserveExpansion == nil {
		return nil
	}
	r.expansion += bytes
	return r.reserveExpansion(r.expansion)
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
	if r.asciiOnly {
		for _, b := range text {
			if b >= 128 {
				return nil, false, ErrNonASCII
			}
		}
		return text, false, nil
	}
	refuse, replace, restore := r.policy.at(r.part, ActionRefuse), r.policy.at(r.part, ActionReplace), r.policy.at(r.part, ActionRestore)
	record := r.policy.at(r.part, ActionRecord)
	if r.piece {
		record = nil
	}
	if refuse == nil && replace == nil && restore == nil && record == nil {
		return text, false, nil
	}
	if refused, err := r.scan(refuse, text); err != nil {
		return nil, false, err
	} else if len(refused) > 0 {
		return nil, false, &RefusedError{Entity: refused[0].entity}
	}
	matches, err := r.scan(replace, text)
	if err != nil {
		return nil, false, err
	}
	if restore != nil {
		restorable, err := r.scan(restore, text)
		if err != nil {
			return nil, false, err
		}
		matches = mergeRestorable(matches, restorable)
	}
	if record != nil {
		recorded, err := r.scan(record, text)
		if err != nil {
			return nil, false, err
		}
		r.recorded = saturatingAdd(r.recorded, unchangedMatches(recorded, matches))
	}
	if len(matches) == 0 {
		return text, false, nil
	}
	if len(matches) > maxMatchesPerText || uint64(r.items)+uint64(len(matches)) > maxMatchesPerRequest {
		return nil, false, ErrMatchLimit
	}

	placeholders := make([]string, len(matches))
	outputSize := len(text)
	for i, found := range matches {
		placeholders[i] = placeholder(found.entity)
		if found.restore {
			numbered, err := r.numbered(found.entity, text[found.start:found.end])
			if err != nil {
				return nil, false, err
			}
			placeholders[i] = numbered
		}
		outputSize += len(placeholders[i]) - (found.end - found.start)
	}
	if outputSize < 0 {
		return nil, false, ErrMatchLimit
	}
	if err := r.reserveGrowth(outputSize - len(text)); err != nil {
		return nil, false, err
	}
	out := make([]byte, 0, outputSize)
	position := 0
	for i, found := range matches {
		out = append(out, text[position:found.start]...)
		out = append(out, placeholders[i]...)
		position = found.end
	}
	out = append(out, text[position:]...)
	r.items += uint32(len(matches))
	return out, true, nil
}

// unchangedMatches counts the recorded matches that no changed match overlaps. Both lists are
// in order and hold no overlap of their own.
func unchangedMatches(recorded, changed []match) uint32 {
	count, next := uint32(0), 0
	for _, found := range recorded {
		for next < len(changed) && changed[next].end <= found.start {
			next++
		}
		if next == len(changed) || changed[next].start >= found.end {
			count++
		}
	}
	return count
}

func saturatingAdd(total, more uint32) uint32 {
	if more > ^uint32(0)-total {
		return ^uint32(0)
	}
	return total + more
}

// scan returns the matches of one set of detectors in text, merged where they overlap.
func (r *Redactor) scan(policy *Policy, text []byte) ([]match, error) {
	if policy == nil || len(text) < policy.minimumBytes {
		return nil, nil
	}
	matches, err := r.scanBuiltinMatches(policy, text)
	if err != nil {
		return nil, err
	}
	// Each requirement scans the original text. A combined alternation would
	// hide overlapping matches from another scope before interval merging.
	for _, expression := range policy.custom {
		matches, err = r.scanCustomPatterns(text, matches, expression)
		if err != nil {
			return nil, err
		}
	}
	longestRun, neededRun := 0, 0
	for _, matcher := range policy.literals {
		neededRun = max(neededRun, matcher.minWordRun)
	}
	if neededRun > 0 {
		longestRun = longestASCIIWordRun(text, neededRun)
	}
	for _, matcher := range policy.literals {
		if matcher.minWordRun > longestRun {
			continue
		}
		matches, err = r.scanLiterals(text, matches, matcher)
		if err != nil {
			return nil, err
		}
	}
	if len(matches) == 0 {
		return nil, nil
	}
	return normalizeMatches(filterEnabledMatches(matches, policy.entities)), nil
}

// mergeRestorable joins the matches that restoring detectors found into those that replacing
// detectors found. A value that a replacing detector reaches is replaced for good, so a
// restoring match that overlaps one joins it, and only the rest get their values back.
func mergeRestorable(replaced, restorable []match) []match {
	if len(restorable) == 0 {
		return replaced
	}
	for i := range restorable {
		restorable[i].restore = true
	}
	if len(replaced) == 0 {
		return restorable
	}
	all := append(replaced, restorable...)
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].start != all[j].start {
			return all[i].start < all[j].start
		}
		return !all[i].restore && all[j].restore
	})
	out := all[:0]
	for _, candidate := range all {
		if len(out) == 0 || candidate.start >= out[len(out)-1].end {
			out = append(out, candidate)
			continue
		}
		current := &out[len(out)-1]
		current.end = max(current.end, candidate.end)
		if current.restore && !candidate.restore {
			current.entity, current.priority, current.restore = candidate.entity, candidate.priority, false
		}
	}
	return out
}

// Built-in PII cannot consist of surrounding whitespace. Retain one original
// boundary byte on either side, so detectors keep their boundary context while
// avoiding a complete padding scan for every detector. Custom rules still see
// the entire original text.
func (r *Redactor) scanBuiltinMatches(policy *Policy, text []byte) ([]match, error) {
	if policy.entities == 0 {
		return nil, nil
	}
	start := max(0, len(text)-len(bytes.TrimLeft(text, " \t\r\n"))-1)
	end := start + len(bytes.TrimRight(text[start:], " \t\r\n"))
	end = min(len(text), end+1)
	matches, err := r.scanBuiltinText(policy, text[start:end])
	for i := range matches {
		matches[i].start += start
		matches[i].end += start
	}
	return matches, err
}

func (r *Redactor) scanBuiltinText(policy *Policy, text []byte) ([]match, error) {
	var matches []match
	var err error
	if policy.entities&secretEntityMask != 0 {
		matches, err = r.scanSecrets(text, matches, policy.entities)
		if err != nil {
			return nil, err
		}
	}
	if policy.entities.has(EntityEmail) {
		matches, err = scanEmails(text, matches)
		if err != nil {
			return nil, err
		}
	}
	if policy.entities.has(EntityIPAddress) {
		matches, err = scanIPAddresses(text, matches)
		if err != nil {
			return nil, err
		}
	}
	if policy.entities&structuredNumberEntityMask != 0 {
		matches, err = scanStructuredNumbers(text, matches, policy.entities)
		if err != nil {
			return nil, err
		}
	}
	if policy.entities&structuredIdentifierEntityMask != 0 {
		matches, err = scanStructuredIdentifiers(text, matches, policy.entities)
		if err != nil {
			return nil, err
		}
	}
	if policy.entities.has(EntityHiddenCharacters) {
		for _, span := range classification.HiddenSpans(text) {
			if matches, err = appendMatch(matches, span.Start, span.End, EntityHiddenCharacters, 1); err != nil {
				return nil, err
			}
		}
	}
	return matches, nil
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
	case EntityHiddenCharacters:
		return "<HIDDEN_CHARACTERS>"
	case EntityCredential:
		return "<CREDENTIAL>"
	case entityCustom:
		return "<CUSTOM_PII>"
	default:
		return "<REDACTED>"
	}
}
