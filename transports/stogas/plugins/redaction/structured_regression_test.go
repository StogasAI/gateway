package redaction

import (
	"bytes"
	"strings"
	"testing"
)

func TestTypedMarkersDoNotInventIdentifierContext(t *testing.T) {
	for _, input := range []string{"001010001 001-01-0001", "001010001 <US_SSN>", "001010001 <PAYMENT_CARD>"} {
		out, _, err := New().redactBytes([]byte(input))
		if err != nil || !bytes.HasPrefix(out, []byte("001010001 ")) {
			t.Fatalf("%q => %q, %v", input, out, err)
		}
	}
	// Window boundaries can cut through a placeholder; its fragment must
	// not supply context either. Real labels outside it still apply.
	for padding := 60; padding < 75; padding++ {
		input := "<US_SSN>" + strings.Repeat(" ", padding) + "001010001"
		out, changed, err := New().redactBytes([]byte(input))
		if err != nil || changed || string(out) != input {
			t.Fatalf("%q => %q, %v", input, out, err)
		}
	}
	out, _, err := New().redactBytes([]byte("SSN: 001010001 <US_SSN>"))
	if err != nil || string(out) != "SSN: <US_SSN> <US_SSN>" {
		t.Fatalf("real context: %q, %v", out, err)
	}
}

func TestInternationalEmailPresentations(t *testing.T) {
	for _, test := range []struct{ source, want string }{
		{"Contact élise@stogas.ai.", "Contact <EMAIL_ADDRESS>."},
		{"Contact 用户@例子.公司.", "Contact <EMAIL_ADDRESS>."},
		{"Contact alice@bücher.de.", "Contact <EMAIL_ADDRESS>."},
		{"Contact e\u0301lise@stogas.ai.", "Contact <EMAIL_ADDRESS>."},
		{"Contact élise@example.com.", "Contact élise@example.com."},
		{"Contact élise@invalid.１２.", "Contact élise@invalid.１２."},
		{strings.Repeat("é", 33) + "@stogas.ai", strings.Repeat("é", 33) + "@stogas.ai"},
	} {
		t.Run(test.source, func(t *testing.T) {
			out, _, err := New().redactBytes([]byte(test.source))
			if err != nil || string(out) != test.want {
				t.Fatalf("got %q, %v; want %q", out, err, test.want)
			}
		})
	}
}

func TestUnicodeNumberPresentations(t *testing.T) {
	for _, test := range []struct{ source, want string }{
		{"Call +44\u00a020\u00a07123\u00a04567.", "Call <PHONE_NUMBER>."},
		{"Call +33\u202f1\u202f42\u202f68\u202f53\u202f00.", "Call <PHONE_NUMBER>."},
		{"Call ＋４４（２０）７１２３４５６７.", "Call <PHONE_NUMBER>."},
		{"SSN ２１９-０９-９９９９", "SSN <US_SSN>"},
		{"SSN ٢١٩-٠٩-٩٩٩٩", "SSN <US_SSN>"},
		{"SSN 𝟚𝟙𝟡-𝟘𝟡-𝟡𝟡𝟡𝟡", "SSN <US_SSN>"},
		{"SSN 219\u201109\u20119999", "SSN <US_SSN>"},
		{"SSN ２１９-０９-９９９９０", "SSN ２１９-０９-９９９９０"},
		{"IDé２１９-０９-９９９９", "IDé２１９-０９-９９９９"},
		{"SSN ６６６-１２-３４５６", "SSN ６６６-１２-３４５６"},
		{"Call +９９９ １２ ３４５ ６７８９.", "Call +９９９ １２ ３４５ ６７８９."},
	} {
		t.Run(test.source, func(t *testing.T) {
			out, _, err := New().redactBytes([]byte(test.source))
			if err != nil || string(out) != test.want {
				t.Fatalf("got %q, %v; want %q", out, err, test.want)
			}
		})
	}
}

func TestPhoneExtensions(t *testing.T) {
	for _, suffix := range []string{" ext. 123", " EXT: 123", " extension 123", " extn 123", "x123", " #123", ";ext=123", " ext. １２３"} {
		input := "Call +44 20 7123 4567" + suffix + "."
		out, _, err := New().redactBytes([]byte(input))
		if err != nil || string(out) != "Call <PHONE_NUMBER>." {
			t.Fatalf("%q => %q, %v", input, out, err)
		}
	}
	for _, suffix := range []string{" next 123", " extra 123", " ext", " ext. 12345678901", " extension\n123"} {
		input := "Call +44 20 7123 4567" + suffix
		out, _, err := New().redactBytes([]byte(input))
		if err != nil || string(out) != "Call <PHONE_NUMBER>"+suffix {
			t.Fatalf("%q => %q, %v", input, out, err)
		}
	}
}

// These cases cover international presentations used by Presidio and common
// E.164 output. Detection remains limited to a leading plus sign or the strict
// North American presentations in structured.go.
func TestInternationalPhonePresentations(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		"Call +55 11 98456 5666.",
		"Call +44 (20) 7123 4567.",
		"Call +44(20)71234567.",
		"Call +91 4155 550132.",
		"Call +49 30 1234567.",
		"Call +49/30/1234567.",
		"Call +39 06 678 4343.",
		"Call +30 21 0 1234567.",
		"Call +33 1 42 68 53 00.",
		"Call +33.1.42.68.53.00.",
		"Call +442079460958.",
		"Call +247 628 9999.",
		"Call +800 1234 5678.",
		"Call +870 773 111 632.",
		"Call +881 612 345 678.",
		"Call +888 123 456 789.",
		"Call +979 123 456 789.",
	} {
		source := source
		t.Run(source, func(t *testing.T) {
			t.Parallel()
			out, changed, err := New().redactBytes([]byte(source))
			if err != nil || !changed || strings.Count(string(out), "<PHONE_NUMBER>") != 1 {
				t.Fatalf("redaction = %q, changed=%t, err=%v", out, changed, err)
			}
		})
	}
}

func TestInvalidInternationalPhonesRemainVisible(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		"The signed date +2026-08-27 remains a date.",
		"Invalid +999 12 345 6789 calling code.",
		"Too short +44 123 456.",
		"Unbalanced +44 (20 7123 4567.",
		"Repeated groups +44 (20) (7123) 4567.",
		"Empty group +44 20()71234567.",
		"Split group +44 (20 7) 1234567.",
		"Separator before country code + 44 20 7123 4567.",
		"Too long +1234567890123456.",
		"Bad NANP +1 112-555-2671.",
		"Unassigned +379 12 345 6789 calling code.",
	} {
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || changed || !bytes.Equal(out, []byte(source)) {
			t.Fatalf("false positive for %q: output=%q changed=%t err=%v", source, out, changed, err)
		}
	}
}

func TestNumericScannerKeepsAdjacentValuesIndependent(t *testing.T) {
	t.Parallel()
	source := []byte("2026-08-27 415-555-2671 212-555-2672")
	redactor := New()
	out, changed, err := redactor.redactBytes(source)
	if err != nil || !changed || string(out) != "2026-08-27 <PHONE_NUMBER> <PHONE_NUMBER>" {
		t.Fatalf("redaction = %q, changed=%t, err=%v", out, changed, err)
	}
	if redactor.Summary().ItemsRedacted != 2 {
		t.Fatalf("items_redacted = %d, want 2", redactor.Summary().ItemsRedacted)
	}
}

func TestSignedDateDoesNotConsumeFollowingPhone(t *testing.T) {
	t.Parallel()
	source := []byte("+2026-08-27 415-555-2671")
	out, changed, err := New().redactBytes(source)
	if err != nil || !changed || string(out) != "+2026-08-27 <PHONE_NUMBER>" {
		t.Fatalf("redaction = %q, changed=%t, err=%v", out, changed, err)
	}
}

func TestCanonicalStructuredPresentations(t *testing.T) {
	t.Parallel()
	positives := []struct {
		source      string
		placeholder string
	}{
		{source: "Canadian SIN 130-692-544", placeholder: "<CA_SOCIAL_INSURANCE_NUMBER>"},
		{source: "Canadian SIN 130692544", placeholder: "<CA_SOCIAL_INSURANCE_NUMBER>"},
		{source: "Aadhaar 9999-9999-0019", placeholder: "<IN_AADHAAR_NUMBER>"},
		{source: "Aadhaar 9999:9999:0019", placeholder: "<IN_AADHAAR_NUMBER>"},
		{source: "SSN 219-09-9999", placeholder: "<US_SSN>"},
		{source: "DNI 55555555-K", placeholder: "<ES_NATIONAL_ID>"},
		{source: "NIE Y8063915-Z", placeholder: "<ES_NATIONAL_ID>"},
	}
	for _, test := range positives {
		out, changed, err := New().redactBytes([]byte(test.source))
		if err != nil || !changed || !bytes.Contains(out, []byte(test.placeholder)) {
			t.Fatalf("redaction of %q = %q, changed=%t, err=%v", test.source, out, changed, err)
		}
	}

	for _, source := range []string{
		"Canadian SIN 130 692-544",
		"Canadian SIN 046 454 286",
		"Canadian SIN 810-214-818",
		"Aadhaar 9999 9999-0019",
		"Aadhaar 99-999999-0019",
		"SSN 666-12-3456",
		"DNI 55555555-A",
		"NIE Y8063915-A",
	} {
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || changed || !bytes.Equal(out, []byte(source)) {
			t.Fatalf("invalid value %q was redacted as %q (changed=%t err=%v)", source, out, changed, err)
		}
	}
}

func TestAmbiguousChecksumValuesRequireSpecificContext(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		"Opaque value 10000000146",
		"Opaque value 12345678903",
		"Opaque value 871220-2384",
		"Opaque value 1234567893",
		"Opaque value 104-86-56659",
		"Opaque value 01333550323",
		"Opaque value 12345678902",
		"Opaque value 1EG4-TE5-MK73",
		"Opaque value A123456780",
		"Opaque value 15070649C103",
	} {
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || changed || !bytes.Equal(out, []byte(source)) {
			t.Fatalf("unlabeled value %q was redacted as %q (changed=%t err=%v)", source, out, changed, err)
		}
	}
}

func TestContextPhrasesAcceptCodeSeparators(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		source      string
		placeholder string
	}{
		{source: `card_number="4532015112830366"`, placeholder: "<PAYMENT_CARD>"},
		{source: `routing_number="021000021"`, placeholder: "<US_ROUTING_NUMBER>"},
		{source: `social-security-number="856456789"`, placeholder: "<US_SSN>"},
		{source: `tax_file_number="123456782"`, placeholder: "<AU_TAX_FILE_NUMBER>"},
		{source: `national-provider-identifier="1234567893"`, placeholder: "<US_NPI>"},
	} {
		out, changed, err := New().redactBytes([]byte(test.source))
		if err != nil || !changed || !bytes.Contains(out, []byte(test.placeholder)) {
			t.Fatalf("redaction of %q = %q, changed=%t, err=%v", test.source, out, changed, err)
		}
	}
}

func TestHighConfidenceHealthIdentifiers(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		source      string
		placeholder string
	}{
		{source: "Krankenkasse KVNR A000500015", placeholder: "<DE_HEALTH_INSURANCE_ID>"},
		{source: "eGK-Nummer m123456785", placeholder: "<DE_HEALTH_INSURANCE_ID>"},
		{source: "Medicare ID 3CD5-FG7-HJ89", placeholder: "<US_MEDICARE_ID>"},
		{source: "The MBI is 4EF6GH8JK12", placeholder: "<US_MEDICARE_ID>"},
		{source: "Sozialversicherungsnummer 65070803A019", placeholder: "<DE_SOCIAL_SECURITY_NUMBER>"},
		{source: "RVNR 38551285K051", placeholder: "<DE_SOCIAL_SECURITY_NUMBER>"},
	} {
		out, changed, err := New().redactBytes([]byte(test.source))
		if err != nil || !changed || !bytes.Contains(out, []byte(test.placeholder)) {
			t.Fatalf("redaction of %q = %q, changed=%t, err=%v", test.source, out, changed, err)
		}
	}
}

func TestThirteenDigitTimestampsAreNotPaymentCards(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		"Timestamp 1748503543012",
		"Card event timestamp 1748503543012",
	} {
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || changed || !bytes.Equal(out, []byte(source)) {
			t.Fatalf("timestamp %q was redacted as %q (changed=%t err=%v)", source, out, changed, err)
		}
	}
}

func TestStructuredNumbersDoNotJoinSeparateValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		source string
		want   string
	}{
		{source: "NPI recorded 2026-08-27 as 1234567893", want: "NPI recorded 2026-08-27 as <US_NPI>"},
		{source: "NHS event 2026-08-27 for 943 476 5919", want: "NHS event 2026-08-27 for <UK_NHS_NUMBER>"},
		{source: "ABA audit 2026-08-27: 021000021", want: "ABA audit 2026-08-27: <US_ROUTING_NUMBER>"},
	}
	for _, test := range tests {
		out, changed, err := New().redactBytes([]byte(test.source))
		if err != nil || !changed || string(out) != test.want {
			t.Fatalf("redaction of %q = %q, changed=%t, err=%v", test.source, out, changed, err)
		}
	}
}

func TestInvalidStructuredNumberGroupingRemainsVisible(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		"NPI 1234/567/893",
		"NHS 943/476/5919",
		"TFN 123-456 782",
		"ABN 51-824 753-556",
		"Korean BRN 104/86/56659",
		"PESEL 440514-01458",
		"TCKN 10000 000146",
		"Partita IVA 01333-550323",
		"Card 4532/0151/1283/0366",
	} {
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || changed || !bytes.Equal(out, []byte(source)) {
			t.Fatalf("invalid grouping %q was redacted as %q (changed=%t err=%v)", source, out, changed, err)
		}
	}
}
