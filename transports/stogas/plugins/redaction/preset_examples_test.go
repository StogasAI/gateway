package redaction

import "testing"

func TestPresetDocumentationExamples(t *testing.T) {
	t.Parallel()
	for _, example := range []struct {
		preset   Pattern
		input    string
		output   string
		negative string
	}{
		{PatternEmailAddress, "Email qa.fixture+redaction@stogas.ai", "Email <EMAIL_ADDRESS>", "Email qa.fixture+redaction@example.com"},
		{PatternPhoneNumber, "Call +44 7700 900123", "Call <PHONE_NUMBER>", "Call +0 7700 900123"},
		{PatternSocialSecurityNumber, "SSN: 856-45-6789", "SSN: <US_SSN>", "SSN: 123-45-6789"},
		{PatternCreditCardNumber, "Card: 4532 0151 1283 0366", "Card: <PAYMENT_CARD>", "Card: 4242 4242 4242 4242"},
		{PatternIPAddress, "IP: 198.51.100.24", "IP: <IP_ADDRESS>", "IP: 198.51.100.256"},
		{PatternAPIKeysAndSecrets, "password=stogas-qa-only-7X!", "password=<CREDENTIAL>", "password=********"},
		{PatternBankIdentifiers, "IBAN GB82 WEST 1234 5698 7654 32", "IBAN <IBAN>", "IBAN GB81 WEST 1234 5698 7654 32"},
		{PatternNationalIdentifiers, "National Insurance AB 12 34 56 C", "National Insurance <UK_NATIONAL_INSURANCE_NUMBER>", "National Insurance QQ 12 34 56 C"},
		{PatternHealthIdentifiers, "NPI 1234567893", "NPI <US_NPI>", "NPI 1234567894"},
	} {
		t.Run(string(example.preset), func(t *testing.T) {
			t.Parallel()
			compiled := mustCompilePolicy(t, Options{Patterns: []Pattern{example.preset}})
			for _, sample := range []struct {
				input, output string
				matches       uint32
			}{
				{example.input, example.output, 1},
				{example.negative, example.negative, 0},
			} {
				redactor := NewWithPolicy(compiled)
				output, changed, err := redactor.redactBytes([]byte(sample.input))
				if err != nil || string(output) != sample.output || changed != (sample.matches > 0) || redactor.Summary().ItemsRedacted != sample.matches {
					t.Fatalf("input=%q output=%q changed=%t summary=%#v err=%v; want %q with %d matches", sample.input, output, changed, redactor.Summary(), err, sample.output, sample.matches)
				}
			}
		})
	}
}
