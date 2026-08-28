package redaction

import "testing"

func TestValidatorRejectsInvalidCheckDigitsAndDates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		valid    string
		invalid  string
		validate func([]byte) bool
	}{
		{name: "payment card", valid: "4532015112830366", invalid: "4532015112830367", validate: paymentCardValid},
		{name: "IBAN", valid: "GB82WEST12345698765432", invalid: "GB81WEST12345698765432", validate: ibanValid},
		{name: "ABA", valid: "021000021", invalid: "021000022", validate: abaRoutingValid},
		{name: "NHS", valid: "9434765919", invalid: "9434765918", validate: nhsNumberValid},
		{name: "Canada SIN", valid: "130692544", invalid: "130692545", validate: canadaSINValid},
		{name: "US NPI", valid: "1234567893", invalid: "1234567894", validate: usNPIValid},
		{name: "Australia TFN", valid: "123456782", invalid: "123456783", validate: australiaTFNValid},
		{name: "Australia ABN", valid: "51824753556", invalid: "51824753557", validate: australiaABNValid},
		{name: "Australia ACN", valid: "004085616", invalid: "004085617", validate: australiaACNValid},
		{name: "Australia Medicare", valid: "2123456701", invalid: "2123456711", validate: australiaMedicareValid},
		{name: "Aadhaar", valid: "999999990019", invalid: "999999990018", validate: aadhaarValid},
		{name: "Brazil CPF", valid: "52998224725", invalid: "52998224724", validate: brazilCPFValid},
		{name: "Brazil CNPJ", valid: "04252011000110", invalid: "04252011000111", validate: brazilCNPJValid},
		{name: "PESEL", valid: "44051401458", invalid: "44051401459", validate: peselValid},
		{name: "Korea RRN", valid: "9001011234568", invalid: "9001011234569", validate: koreaRRNValid},
		{name: "Korea FRN", valid: "9111245678906", invalid: "9111245678901", validate: koreaRRNValid},
		{name: "Thailand ID", valid: "1220000000007", invalid: "1280000000007", validate: thailandIDValid},
		{name: "China ID", valid: "11010519491231002X", invalid: "11010519490231002X", validate: chinaResidentIDValid},
		{name: "Israel ID", valid: "123456782", invalid: "123456783", validate: israelIDValid},
		{name: "South Africa ID", valid: "8001015009087", invalid: "8001015009088", validate: southAfricaIDValid},
		{name: "Turkey national ID", valid: "10000000146", invalid: "10000000147", validate: turkeyNationalIDValid},
		{name: "Germany tax ID", valid: "12345678903", invalid: "12345678904", validate: germanyTaxIDValid},
		{name: "Sweden personal ID", valid: "8712202384", invalid: "8712202385", validate: func(value []byte) bool {
			return swedenPersonalIDValid(value, value)
		}},
		{name: "Korea business number", valid: "1048656659", invalid: "1048656658", validate: koreaBusinessNumberValid},
		{name: "Italy VAT", valid: "01333550323", invalid: "01333550324", validate: italyVATValid},
		{name: "Nigeria NIN", valid: "12345678902", invalid: "12345678901", validate: nigeriaNINValid},
		{name: "Germany health insurance", valid: "A123456780", invalid: "A123456787", validate: germanyHealthInsuranceValid},
		{name: "Germany social security", valid: "15070649C103", invalid: "15070649C100", validate: germanySocialSecurityValid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if !test.validate([]byte(test.valid)) {
				t.Fatalf("valid test value %q was rejected", test.valid)
			}
			if test.validate([]byte(test.invalid)) {
				t.Fatalf("invalid test value %q was accepted", test.invalid)
			}
		})
	}
}

func TestNumericCheckDigitsRejectEveryWrongDigit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		valid    string
		validate func([]byte) bool
	}{
		{name: "payment card", valid: "4532015112830366", validate: paymentCardValid},
		{name: "ABA", valid: "021000021", validate: abaRoutingValid},
		{name: "NHS", valid: "9434765919", validate: nhsNumberValid},
		{name: "Canada SIN", valid: "130692544", validate: canadaSINValid},
		{name: "US NPI", valid: "1234567893", validate: usNPIValid},
		{name: "Australia TFN", valid: "123456782", validate: australiaTFNValid},
		{name: "Australia ABN", valid: "51824753556", validate: australiaABNValid},
		{name: "Australia ACN", valid: "004085616", validate: australiaACNValid},
		{name: "Aadhaar", valid: "999999990019", validate: aadhaarValid},
		{name: "Brazil CPF", valid: "52998224725", validate: brazilCPFValid},
		{name: "Brazil CNPJ", valid: "04252011000110", validate: brazilCNPJValid},
		{name: "PESEL", valid: "44051401458", validate: peselValid},
		{name: "Korea RRN", valid: "9001011234568", validate: koreaRRNValid},
		{name: "Korea business number", valid: "1048656659", validate: koreaBusinessNumberValid},
		{name: "Thailand ID", valid: "1220000000007", validate: thailandIDValid},
		{name: "Israel ID", valid: "123456782", validate: israelIDValid},
		{name: "South Africa ID", valid: "8001015009087", validate: southAfricaIDValid},
		{name: "Turkey national ID", valid: "10000000146", validate: turkeyNationalIDValid},
		{name: "Germany tax ID", valid: "12345678903", validate: germanyTaxIDValid},
		{name: "Sweden personal ID", valid: "8712202384", validate: func(value []byte) bool {
			return swedenPersonalIDValid(value, value)
		}},
		{name: "Italy VAT", valid: "01333550323", validate: italyVATValid},
		{name: "Nigeria NIN", valid: "12345678902", validate: nigeriaNINValid},
		{name: "Germany health insurance", valid: "A123456780", validate: germanyHealthInsuranceValid},
		{name: "Germany social security", valid: "15070649C103", validate: germanySocialSecurityValid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if !test.validate([]byte(test.valid)) {
				t.Fatalf("valid test value %q was rejected", test.valid)
			}
			for replacement := byte('0'); replacement <= '9'; replacement++ {
				if replacement == test.valid[len(test.valid)-1] {
					continue
				}
				mutated := []byte(test.valid)
				mutated[len(mutated)-1] = replacement
				if test.validate(mutated) {
					t.Fatalf("wrong check digit was accepted: %q", mutated)
				}
			}
		})
	}
}

func TestAustraliaMedicareChecksumAndIssueNumber(t *testing.T) {
	t.Parallel()
	for issueNumber := byte('1'); issueNumber <= '9'; issueNumber++ {
		value := []byte("2123456701")
		value[9] = issueNumber
		if !australiaMedicareValid(value) {
			t.Fatalf("valid issue number was rejected: %q", value)
		}
	}
	for replacement := byte('1'); replacement <= '9'; replacement++ {
		value := []byte("2123456701")
		value[8] = replacement
		if australiaMedicareValid(value) {
			t.Fatalf("wrong checksum digit was accepted: %q", value)
		}
	}
	if australiaMedicareValid([]byte("2123456700")) {
		t.Fatal("zero issue number was accepted")
	}
}

func TestExtendedValidatorCases(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"219099999", "856456789"} {
		if !usSSNValid([]byte(value)) {
			t.Fatalf("valid SSN value %q was rejected", value)
		}
	}
	for _, value := range []string{"078051120", "123456789", "987654320", "987654321", "000123456", "666123456", "900123456"} {
		if usSSNValid([]byte(value)) {
			t.Fatalf("invalid or canonical sample SSN %q was accepted", value)
		}
	}
	for _, value := range []string{"911531234", "900701234", "900901234", "900941234"} {
		if !usITINValid([]byte(value)) {
			t.Fatalf("valid ITIN range value %q was rejected", value)
		}
	}
	for _, value := range []string{"900491234", "900661234", "900891234", "900931234"} {
		if usITINValid([]byte(value)) {
			t.Fatalf("invalid ITIN range value %q was accepted", value)
		}
	}
	if abaRoutingValid([]byte("991234561")) {
		t.Fatal("routing number with an unassigned prefix was accepted")
	}
	for _, value := range []string{"046454286", "810214818"} {
		if canadaSINValid([]byte(value)) {
			t.Fatalf("reserved Canadian SIN %q was accepted", value)
		}
	}
	for _, value := range []string{"12345678902", "98765432102", "55512345672", "01234567895"} {
		if !nigeriaNINValid([]byte(value)) {
			t.Fatalf("valid Nigerian NIN %q was rejected", value)
		}
	}
	if nigeriaNINValid([]byte("00000000000")) {
		t.Fatal("all-zero Nigerian NIN was accepted")
	}
	for _, value := range []string{"1EG4-TE5-MK73", "1EG4TE5MK73", "2AG9-XC4-NN22", "1eg4-te5-mk73"} {
		if !usMedicareIDValid([]byte(value)) {
			t.Fatalf("valid Medicare beneficiary ID %q was rejected", value)
		}
	}
	for _, value := range []string{
		"1SG4-TE5-MK73", "1EG4-LE5-MK73", "1EG4-TE5-OK73", "1EG4-TE5-MI73",
		"1BG4-TE5-MK73", "1EG4-ZE5-MK73", "AEG4-TE5-MK73", "12G4-TE5-MK73",
		"1EG4TE5MK7", "1EG4TE5MK734",
	} {
		if usMedicareIDValid([]byte(value)) {
			t.Fatalf("invalid Medicare beneficiary ID %q was accepted", value)
		}
	}
	for _, value := range []string{"A000500015", "C000500021", "A123456780", "B123456782", "M123456785", "Z000000005", "Z999999997", "a123456780"} {
		if !germanyHealthInsuranceValid([]byte(value)) {
			t.Fatalf("valid German health insurance number %q was rejected", value)
		}
	}
	for _, value := range []string{"15070649C103", "65070803A019", "20151090B023", "38551285K051", "15070649c103"} {
		if !germanySocialSecurityValid([]byte(value)) {
			t.Fatalf("valid German social security number %q was rejected", value)
		}
	}
	for _, value := range []string{"15070649C100", "15070049C103", "15071349C103", "15420649C103", "15850649C103", "00070649C103"} {
		if germanySocialSecurityValid([]byte(value)) {
			t.Fatalf("invalid German social security number %q was accepted", value)
		}
	}
	for _, code := range []string{"11", "23", "37", "46", "54", "65", "71", "81", "82"} {
		if !chinaProvinceCodeValid([]byte(code)) {
			t.Fatalf("valid Chinese province code %q was rejected", code)
		}
	}
	for _, code := range []string{"00", "20", "30", "40", "55", "66", "72", "80", "83", "99"} {
		if chinaProvinceCodeValid([]byte(code)) {
			t.Fatalf("invalid Chinese province code %q was accepted", code)
		}
	}
	for _, value := range []string{"1220000000007", "1520000000004", "1580000000004"} {
		if !thailandIDValid([]byte(value)) {
			t.Fatalf("valid Thai province value %q was rejected", value)
		}
	}
	if peselValid([]byte("44023101452")) {
		t.Fatal("PESEL with an impossible date was accepted")
	}
	if koreaRRNValid([]byte("9002311234567")) {
		t.Fatal("Korean RRN with an impossible date was accepted")
	}
	if !southAfricaIDValid([]byte("0001015002288")) {
		t.Fatal("valid South African refugee ID was rejected")
	}
	for _, value := range []string{"010594Y9032", "020594X903P", "030594W903B", "020504A902E"} {
		if !finlandIDValid([]byte(value)) {
			t.Fatalf("valid Finnish personal ID %q was rejected", value)
		}
	}
	for _, value := range []string{"010594G9032", "131052/308T", "290200+311B", "290201A0011"} {
		if finlandIDValid([]byte(value)) {
			t.Fatalf("invalid Finnish personal ID %q was accepted", value)
		}
	}
	for _, value := range []string{"8713322384", "8702302384", "8712602384"} {
		if swedenPersonalIDValid([]byte(value), []byte(value)) {
			t.Fatalf("invalid Swedish personal ID %q was accepted", value)
		}
	}
}

func TestPaymentCardNetworkAndLengthCoverage(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"111111111111119",
		"4111111111119",
		"411111111111111118",
		"2221111111111112",
		"341111111111111",
		"3001111111111116",
		"3611111111111111110",
		"6011111111111111110",
		"35281111111111119",
		"5011111111111119",
		"6711111111111111115",
		"22001111111111116",
		"8101111111111114",
		"9792111111111116",
	} {
		if !paymentCardValid([]byte(value)) {
			t.Fatalf("valid payment network number %q was rejected", value)
		}
	}
	for _, value := range []string{"1748503543012", "7111111111111114", "9793111111111115"} {
		if paymentCardValid([]byte(value)) {
			t.Fatalf("non-card number %q was accepted", value)
		}
	}
}

func TestCallingCodeInventoryMatchesLibphonenumber(t *testing.T) {
	t.Parallel()
	count := 0
	for value := 1; value <= 999; value++ {
		if callingCodeValid(value) {
			count++
		}
	}
	if count != 215 {
		t.Fatalf("calling-code inventory has %d entries, want 215", count)
	}
	for _, value := range []int{247, 800, 808, 870, 878, 881, 882, 883, 888, 979} {
		if !callingCodeValid(value) {
			t.Errorf("assigned calling code +%d is missing", value)
		}
	}
	for _, value := range []int{0, 210, 259, 280, 292, 379, 384, 388, 671, 684, 999} {
		if callingCodeValid(value) {
			t.Errorf("unassigned calling code +%d was accepted", value)
		}
	}
}

func TestDigitValidatorsRejectNonDigits(t *testing.T) {
	t.Parallel()
	validators := []func([]byte) bool{
		paymentCardValid, abaRoutingValid, nhsNumberValid, canadaSINValid, usNPIValid, australiaTFNValid, australiaABNValid,
		australiaACNValid, australiaMedicareValid, aadhaarValid, brazilCPFValid, brazilCNPJValid,
		peselValid, koreaRRNValid, thailandIDValid, israelIDValid, southAfricaIDValid,
		turkeyNationalIDValid, germanyTaxIDValid, koreaBusinessNumberValid, italyVATValid, nigeriaNINValid,
	}
	for _, validate := range validators {
		if validate([]byte("AAAAAAAAAAAAAAAAAAA")) {
			t.Fatal("validator accepted non-digit input")
		}
	}
}

func TestCalendarValidation(t *testing.T) {
	t.Parallel()
	for _, valid := range []string{"20000229", "19491231", "21991231"} {
		if !validYYYYMMDD([]byte(valid)) {
			t.Fatalf("valid date %s was rejected", valid)
		}
	}
	for _, invalid := range []string{"19000229", "20010229", "20260431", "17991231", "22000101"} {
		if validYYYYMMDD([]byte(invalid)) {
			t.Fatalf("invalid date %s was accepted", invalid)
		}
	}
}

func TestIBANCountryLengthsMatchSWIFTRegistry(t *testing.T) {
	t.Parallel()
	// SWIFT IBAN Registry release 101 (December 2025).
	expected := map[string]int{
		"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28,
		"BA": 20, "BE": 16, "BG": 22, "BH": 22, "BI": 27, "BR": 29, "BY": 28,
		"CH": 21, "CR": 22, "CY": 28, "CZ": 24,
		"DE": 22, "DJ": 27, "DK": 18, "DO": 28,
		"EE": 20, "EG": 29, "ES": 24,
		"FI": 18, "FK": 18, "FO": 18, "FR": 27,
		"GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
		"HN": 28, "HR": 21, "HU": 28,
		"IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27,
		"JO": 30, "KW": 30, "KZ": 20,
		"LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25,
		"MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27, "MT": 31, "MU": 30,
		"NI": 28, "NL": 18, "NO": 15, "OM": 23,
		"PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29,
		"RO": 24, "RS": 22, "RU": 33,
		"SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25, "SV": 28,
		"TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20, "YE": 30,
	}
	if len(expected) != 89 {
		t.Fatalf("registry fixture has %d countries, want 89", len(expected))
	}
	for country, length := range expected {
		if got := ibanCountryLength(country[0], country[1]); got != length {
			t.Errorf("%s length = %d, want %d", country, got, length)
		}
	}
	for _, country := range []string{"CA", "JP", "US", "ZZ"} {
		if got := ibanCountryLength(country[0], country[1]); got != 0 {
			t.Errorf("unregistered country %s has length %d", country, got)
		}
	}
}

func TestRecentSWIFTIBANExamples(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"BI4210000100010000332045181",
		"DJ2100010000000154000100186",
		"FK88SC123456789012",
		"HN88CABF00000000000250005469",
		"MN121234123456789123",
		"NI45BAPR00000013000003558124",
		"OM810180000001299123456",
		"RU0304452522540817810538091310419",
		"SO211000001001000100141",
		"YE15CBYE0001018861234567891234",
	} {
		if !ibanValid([]byte(value)) {
			t.Errorf("official SWIFT example %q was rejected", value)
		}
	}
}
