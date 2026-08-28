package redaction

func scanEmails(text []byte, matches []match) ([]match, error) {
	for at := 0; at < len(text); at++ {
		if text[at] != '@' {
			continue
		}
		start := at
		for start > 0 && at-start < 64 && isEmailLocalByte(text[start-1]) {
			start--
		}
		end := at + 1
		for end < len(text) && end-at <= 254 && isEmailDomainByte(text[end]) {
			end++
		}
		scannedEnd := end
		for end > at+1 && (text[end-1] == '.' || text[end-1] == '-') {
			end--
		}
		if !emailValid(text[start:end], at-start) || !wordBoundaryBeforeEmail(text, start) || !wordBoundaryAfterEmail(text, end, scannedEnd) {
			continue
		}
		var err error
		matches, err = appendMatch(matches, start, end, EntityEmail, 80)
		if err != nil {
			return nil, err
		}
	}
	return matches, nil
}

func isEmailLocalByte(value byte) bool {
	if isASCIIAlphanumeric(value) {
		return true
	}
	switch value {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~', '.':
		return true
	default:
		return false
	}
}

func isEmailDomainByte(value byte) bool {
	return isASCIIAlphanumeric(value) || value == '-' || value == '.'
}

func wordBoundaryBeforeEmail(text []byte, start int) bool {
	return start == 0 || !isEmailLocalByte(text[start-1])
}

func wordBoundaryAfterEmail(text []byte, end, scannedEnd int) bool {
	if scannedEnd > end {
		end = scannedEnd
	}
	return end == len(text) || !isEmailDomainByte(text[end]) && !isIdentifierByte(text[end])
}

func emailValid(value []byte, at int) bool {
	if at < 1 || at > 64 || len(value)-at-1 < 4 || len(value) > 320 {
		return false
	}
	local := value[:at]
	domain := value[at+1:]
	if local[0] == '.' || local[len(local)-1] == '.' {
		return false
	}
	for index := 1; index < len(local); index++ {
		if local[index] == '.' && local[index-1] == '.' {
			return false
		}
	}
	lastDot := -1
	labelStart := 0
	for index, character := range domain {
		if character != '.' {
			continue
		}
		if index == labelStart || index-labelStart > 63 || domain[labelStart] == '-' || domain[index-1] == '-' {
			return false
		}
		lastDot = index
		labelStart = index + 1
	}
	if lastDot < 1 || labelStart >= len(domain) || len(domain)-labelStart > 63 || domain[labelStart] == '-' || domain[len(domain)-1] == '-' {
		return false
	}
	tld := domain[lastDot+1:]
	if len(tld) < 2 || len(tld) > 63 {
		return false
	}
	if !hasPrefixFoldASCII(tld, "xn--") {
		for _, character := range tld {
			if !isASCIILetter(character) {
				return false
			}
		}
	}
	return !reservedEmailDomain(domain)
}

func reservedEmailDomain(domain []byte) bool {
	for _, reserved := range []string{"example.com", "example.net", "example.org", "example.edu", "example.invalid", "localhost"} {
		if equalFoldASCII(domain, reserved) {
			return true
		}
	}
	for _, suffix := range []string{".example.com", ".example.net", ".example.org", ".example.edu", ".example", ".invalid", ".localhost", ".test"} {
		if len(domain) >= len(suffix) && equalFoldASCII(domain[len(domain)-len(suffix):], suffix) {
			return true
		}
	}
	return false
}

func scanStructuredNumbers(text []byte, matches []match, enabled entityMask) ([]match, error) {
	for start := 0; start < len(text); start++ {
		if !isASCIIDigit(text[start]) && text[start] != '+' && !(text[start] == '(' && start+1 < len(text) && isASCIIDigit(text[start+1])) {
			continue
		}
		if start > 0 && isIdentifierByte(text[start-1]) {
			continue
		}

		// A space or dash can terminate one number and also separate groups
		// inside it. Test each digit boundary instead of consuming one maximal
		// run. This keeps adjacent values independent and finds a number after a
		// date without backtracking over unbounded input.
		var digitBuffer [19]byte
		digits := digitBuffer[:0]
		limit := start + 48
		if limit > len(text) {
			limit = len(text)
		}
		for end := start; end < limit && isStructuredNumberByte(text[end]); end++ {
			if !isASCIIDigit(text[end]) {
				continue
			}
			if len(digits) == cap(digits) {
				break
			}
			digits = append(digits, text[end])
			if len(digits) < 9 || end+1 < len(text) && isIdentifierByte(text[end+1]) {
				continue
			}
			var err error
			matches, err = classifyStructuredNumber(text, start, end+1, text[start:end+1], digits, matches, enabled)
			if err != nil {
				return nil, err
			}
		}
	}
	return matches, nil
}

func isStructuredNumberByte(value byte) bool {
	if isASCIIDigit(value) {
		return true
	}
	switch value {
	case '+', ' ', '\t', '-', '.', '/', ':', '(', ')':
		return true
	default:
		return false
	}
}

func classifyStructuredNumber(text []byte, start, end int, raw, digits []byte, matches []match, enabled entityMask) ([]match, error) {
	add := func(entity Entity, priority uint8) error {
		if !enabled.has(entity) {
			return nil
		}
		var err error
		matches, err = appendMatch(matches, start, end, entity, priority)
		return err
	}

	cardContext := hasNearbyContext(text, start, end, "card", "credit card", "debit card", "pan", "visa", "mastercard", "amex", "discover", "jcb", "diners", "maestro")
	if paymentCardValid(digits) && !knownTestPaymentCard(digits) && (formattedPaymentCard(raw) || allASCIIDigits(raw) && cardContext) {
		if err := add(EntityPaymentCard, 86); err != nil {
			return nil, err
		}
	}
	if internationalPhoneValid(raw, digits) || northAmericanPhoneValid(raw, digits) {
		if err := add(EntityPhone, 72); err != nil {
			return nil, err
		}
	}

	switch len(digits) {
	case 9:
		if usSSNValid(digits) && (ssnFormatted(raw) || ssnPresentationValid(raw) && hasNearbyContext(text, start, end, "ssn", "social security")) {
			if err := add(EntityUSSSN, 78); err != nil {
				return nil, err
			}
		}
		if usITINValid(digits) && (ssnFormatted(raw) || ssnPresentationValid(raw) && hasNearbyContext(text, start, end, "itin", "taxpayer identification")) {
			if err := add(EntityUSITIN, 79); err != nil {
				return nil, err
			}
		}
		if abaRoutingValid(digits) && abaPresentationValid(raw) && hasNearbyContext(text, start, end, "aba", "routing number", "routing transit") {
			if err := add(EntityUSRoutingNumber, 77); err != nil {
				return nil, err
			}
		}
		if canadaSINValid(digits) && canadaSINPresentationValid(raw) && hasNearbyContext(
			text, start, end,
			"sin number", "social insurance", "canadian sin", "canada sin", "numéro nas", "assurance sociale",
		) {
			if err := add(EntityCanadaSIN, 77); err != nil {
				return nil, err
			}
		}
		if australiaTFNValid(digits) && digitsOrGrouped(raw, 3, 3, 3) && hasNearbyContext(text, start, end, "tfn", "tax file number") {
			if err := add(EntityAustraliaTFN, 77); err != nil {
				return nil, err
			}
		}
		if australiaACNValid(digits) && digitsOrGrouped(raw, 3, 3, 3) && hasNearbyContext(text, start, end, "acn", "australian company number") {
			if err := add(EntityAustraliaACN, 77); err != nil {
				return nil, err
			}
		}
		if israelIDValid(digits) && allASCIIDigits(raw) && hasNearbyContext(text, start, end, "israeli id", "identity number", "teudat zehut") {
			if err := add(EntityIsraelNationalID, 77); err != nil {
				return nil, err
			}
		}
	case 10:
		if nhsNumberValid(digits) && digitsOrGrouped(raw, 3, 3, 4) && hasNearbyContext(text, start, end, "nhs", "national health service") {
			if err := add(EntityUKNHS, 77); err != nil {
				return nil, err
			}
		}
		if australiaMedicareValid(digits) && digitsOrGrouped(raw, 4, 5, 1) && hasNearbyContext(text, start, end, "medicare") {
			if err := add(EntityAustraliaMedicare, 77); err != nil {
				return nil, err
			}
		}
		if usNPIValid(digits) && digitsOrGrouped(raw, 4, 3, 3) && hasNearbyContext(text, start, end, "npi", "national provider identifier", "provider identifier") {
			if err := add(EntityUSNPI, 78); err != nil {
				return nil, err
			}
		}
		if koreaBusinessNumberValid(digits) && digitsOrGrouped(raw, 3, 2, 5) && hasNearbyContext(
			text, start, end, "korean brn", "business registration number", "사업자등록번호", "사업자번호",
		) {
			if err := add(EntityKoreaBusinessNumber, 78); err != nil {
				return nil, err
			}
		}
		if swedenPersonalIDValid(raw, digits) && hasNearbyContext(
			text, start, end, "personnummer", "svenskt personnummer", "svensk id", "swedish personal id", "samordningsnummer",
		) {
			if err := add(EntitySwedenPersonalID, 78); err != nil {
				return nil, err
			}
		}
	case 11:
		if australiaABNValid(digits) && digitsOrGrouped(raw, 2, 3, 3, 3) && hasNearbyContext(text, start, end, "abn", "australian business number") {
			if err := add(EntityAustraliaABN, 77); err != nil {
				return nil, err
			}
		}
		if brazilCPFValid(digits) && (cpfFormatted(raw) || allASCIIDigits(raw) && hasNearbyContext(text, start, end, "cpf", "cadastro de pessoas")) {
			if err := add(EntityBrazilCPF, 79); err != nil {
				return nil, err
			}
		}
		if peselValid(digits) && allASCIIDigits(raw) && hasNearbyContext(text, start, end, "pesel") {
			if err := add(EntityPolandPESEL, 77); err != nil {
				return nil, err
			}
		}
		if turkeyNationalIDValid(digits) && allASCIIDigits(raw) && hasNearbyContext(
			text, start, end, "tckn", "tc kimlik", "kimlik no", "turkish id", "türk kimlik",
		) {
			if err := add(EntityTurkeyNationalID, 78); err != nil {
				return nil, err
			}
		}
		if germanyTaxIDValid(digits) && allASCIIDigits(raw) && hasNearbyContext(
			text, start, end, "steueridentifikationsnummer", "steuer-id", "steuerid", "idnr", "german tax id",
		) {
			if err := add(EntityGermanyTaxID, 78); err != nil {
				return nil, err
			}
		}
		if italyVATValid(digits) && allASCIIDigits(raw) && hasNearbyContext(text, start, end, "partita iva", "piva", "italian vat") {
			if err := add(EntityItalyVAT, 78); err != nil {
				return nil, err
			}
		}
		if nigeriaNINValid(digits) && allASCIIDigits(raw) && hasNearbyContext(
			text, start, end, "nigerian nin", "nigeria nin", "nimc", "nigeria id", "nigerian identification", "nigerian national identification number",
		) {
			if err := add(EntityNigeriaNIN, 78); err != nil {
				return nil, err
			}
		}
	case 12:
		if aadhaarValid(digits) && aadhaarPresentationValid(raw) && hasNearbyContext(text, start, end, "aadhaar", "aadhar", "uidai") {
			if err := add(EntityIndiaAadhaar, 77); err != nil {
				return nil, err
			}
		}
		if swedenPersonalIDValid(raw, digits) && hasNearbyContext(
			text, start, end, "personnummer", "svenskt personnummer", "svensk id", "swedish personal id", "samordningsnummer",
		) {
			if err := add(EntitySwedenPersonalID, 78); err != nil {
				return nil, err
			}
		}
	case 13:
		koreaContext := hasNearbyContext(
			text, start, end,
			"korean rrn", "rrn", "resident registration", "주민등록번호",
			"korean frn", "frn", "foreigner registration", "외국인등록번호",
		)
		if (koreaRRNValid(digits) && (koreaRRNFormatted(raw) || koreaContext)) ||
			(koreaRegistrationStructureValid(digits) && koreaRRNFormatted(raw) && koreaContext) {
			if err := add(EntityKoreaRRN, 79); err != nil {
				return nil, err
			}
		}
		if thailandIDValid(digits) && (thailandIDFormatted(raw) || hasNearbyContext(
			text, start, end, "tnin", "thai national id", "เลขประจำตัวประชาชน", "เลขบัตรประชาชน", "รหัสปชช",
		)) {
			if err := add(EntityThailandNationalID, 78); err != nil {
				return nil, err
			}
		}
		if southAfricaIDValid(digits) && allASCIIDigits(raw) && hasNearbyContext(
			text, start, end, "south african id", "rsa id", "za id", "identity number", "permanent resident number", "refugee id",
		) {
			if err := add(EntitySouthAfricaID, 77); err != nil {
				return nil, err
			}
		}
	case 14:
		if brazilCNPJValid(digits) && (cnpjFormatted(raw) || allASCIIDigits(raw) && hasNearbyContext(text, start, end, "cnpj", "cadastro nacional")) {
			if err := add(EntityBrazilCNPJ, 79); err != nil {
				return nil, err
			}
		}
	}
	return matches, nil
}

func formattedPaymentCard(raw []byte) bool {
	return groupedDigitsValid(raw, 4, 4, 4, 4) ||
		groupedDigitsValid(raw, 4, 4, 4, 1) || groupedDigitsValid(raw, 4, 4, 5) ||
		groupedDigitsValid(raw, 4, 6, 4) || groupedDigitsValid(raw, 4, 6, 5) || groupedDigitsValid(raw, 4, 5, 6) ||
		groupedDigitsValid(raw, 4, 4, 4, 5) || groupedDigitsValid(raw, 4, 4, 4, 6) || groupedDigitsValid(raw, 4, 4, 4, 7)
}

func knownTestPaymentCard(digits []byte) bool {
	for _, value := range []string{
		"4111111111111111", "4242424242424242", "4000056655665556", "5555555555554444",
		"378282246310005", "6011111111111117", "30569309025904", "3566002020360505",
		"4012888888881881", "371449635398431", "5019717010103742", "6011000400000000",
		"3528000700000000", "6759649826438453", "4917300800000000", "4484070000000000",
		"122000000000003",
	} {
		if equalFoldASCII(digits, value) {
			return true
		}
	}
	return false
}

func ssnFormatted(raw []byte) bool {
	return len(raw) == 11 && raw[3] == '-' && raw[6] == '-'
}

func ssnPresentationValid(raw []byte) bool {
	return allASCIIDigits(raw) || groupedDigitsWithSeparator(raw, '-', 3, 2, 4) ||
		groupedDigitsWithSeparator(raw, ' ', 3, 2, 4) || groupedDigitsWithSeparator(raw, '.', 3, 2, 4) ||
		groupedDigitsWithSeparator(raw, '-', 5, 4) || groupedDigitsWithSeparator(raw, '-', 3, 6)
}

func abaPresentationValid(raw []byte) bool {
	return allASCIIDigits(raw) || groupedDigitsWithSeparator(raw, '-', 4, 4, 1)
}

func digitsOrGrouped(raw []byte, groups ...int) bool {
	return allASCIIDigits(raw) || groupedDigitsValid(raw, groups...)
}

func groupedDigitsValid(raw []byte, groups ...int) bool {
	return groupedDigitsWithSeparator(raw, ' ', groups...) || groupedDigitsWithSeparator(raw, '-', groups...)
}

func groupedDigitsWithSeparator(raw []byte, separator byte, groups ...int) bool {
	expected := len(groups) - 1
	for _, group := range groups {
		if group < 1 {
			return false
		}
		expected += group
	}
	if len(groups) < 2 || len(raw) != expected {
		return false
	}
	position := 0
	for groupIndex, group := range groups {
		for range group {
			if !isASCIIDigit(raw[position]) {
				return false
			}
			position++
		}
		if groupIndex+1 < len(groups) {
			if raw[position] != separator {
				return false
			}
			position++
		}
	}
	return true
}

func canadaSINPresentationValid(raw []byte) bool {
	if len(raw) == 9 {
		return allASCIIDigits(raw)
	}
	if len(raw) != 11 || (raw[3] != ' ' && raw[3] != '-') || raw[7] != raw[3] {
		return false
	}
	return digitsAtAllOtherPositions(raw, 3, 7)
}

func aadhaarPresentationValid(raw []byte) bool {
	if len(raw) == 12 {
		return allASCIIDigits(raw)
	}
	if len(raw) != 14 || (raw[4] != ' ' && raw[4] != '-' && raw[4] != ':') || raw[9] != raw[4] {
		return false
	}
	return digitsAtAllOtherPositions(raw, 4, 9)
}

func cpfFormatted(raw []byte) bool {
	return len(raw) == 14 && raw[3] == '.' && raw[7] == '.' && raw[11] == '-'
}

func cnpjFormatted(raw []byte) bool {
	return len(raw) == 18 && raw[2] == '.' && raw[6] == '.' && raw[10] == '/' && raw[15] == '-'
}

func koreaRRNFormatted(raw []byte) bool {
	return len(raw) == 14 && raw[6] == '-'
}

func thailandIDFormatted(raw []byte) bool {
	return len(raw) == 17 && raw[1] == '-' && raw[6] == '-' && raw[12] == '-' && raw[15] == '-'
}

func northAmericanPhoneValid(raw, digits []byte) bool {
	presentation := raw
	if len(digits) == 11 && digits[0] == '1' {
		digits = digits[1:]
		switch {
		case len(raw) > 3 && raw[0] == '+' && raw[1] == '1' && (raw[2] == ' ' || raw[2] == '-'):
			presentation = raw[3:]
		case len(raw) > 2 && raw[0] == '1' && (raw[1] == ' ' || raw[1] == '-'):
			presentation = raw[2:]
		default:
			return false
		}
	}
	if !northAmericanDigitsValid(digits) {
		return false
	}
	if len(presentation) == 12 {
		separator := presentation[3]
		if (separator != '-' && separator != '.' && separator != ' ') || presentation[7] != separator {
			return false
		}
		return digitsAtAllOtherPositions(presentation, 3, 7)
	}
	if len(presentation) == 13 && presentation[0] == '(' && presentation[4] == ')' && presentation[8] == '-' {
		return digitsAtAllOtherPositions(presentation, 0, 4, 8)
	}
	if len(presentation) == 14 && presentation[0] == '(' && presentation[4] == ')' && (presentation[5] == ' ' || presentation[5] == '-') && presentation[9] == '-' {
		return digitsAtAllOtherPositions(presentation, 0, 4, 5, 9)
	}
	return false
}

func northAmericanDigitsValid(digits []byte) bool {
	if len(digits) != 10 || allEqual(digits) || digits[0] < '2' || digits[3] < '2' ||
		(digits[1] == '1' && digits[2] == '1') || (digits[4] == '1' && digits[5] == '1') {
		return false
	}
	return !(digits[3] == '5' && digits[4] == '5' && digits[5] == '5' && digits[6] == '0' && digits[7] == '1')
}

func digitsAtAllOtherPositions(value []byte, separators ...int) bool {
	next := 0
	for index, character := range value {
		if next < len(separators) && index == separators[next] {
			next++
			continue
		}
		if !isASCIIDigit(character) {
			return false
		}
	}
	return next == len(separators)
}

func internationalPhoneValid(raw, digits []byte) bool {
	if len(raw) < 2 || raw[0] != '+' || !isASCIIDigit(raw[1]) || len(digits) < 10 || len(digits) > 15 || digits[0] == '0' || allEqual(digits) ||
		!validCallingCode(digits) || signedISODatePrefix(raw) {
		return false
	}
	if digits[0] == '1' && (len(digits) != 11 || !northAmericanDigitsValid(digits[1:])) {
		return false
	}
	separators := 0
	parentheses := 0
	parenthesisPairs := 0
	digitCount := 0
	parenthesisDigitStart := 0
	for _, character := range raw[1:] {
		switch {
		case isASCIIDigit(character):
			digitCount++
		case character == ' ' || character == '-' || character == '.' || character == '/':
			if parentheses != 0 {
				return false
			}
			separators++
		case character == '(':
			parentheses++
			parenthesisPairs++
			parenthesisDigitStart = digitCount
			if parentheses > 1 || parenthesisPairs > 1 || digitCount == 0 {
				return false
			}
		case character == ')':
			if parentheses != 1 || digitCount-parenthesisDigitStart < 1 || digitCount-parenthesisDigitStart > 5 {
				return false
			}
			parentheses--
		default:
			return false
		}
	}
	return parentheses == 0 && (separators > 0 || parenthesisPairs == 1 || len(raw) == len(digits)+1)
}

func signedISODatePrefix(raw []byte) bool {
	return len(raw) >= 11 && raw[0] == '+' && raw[5] == '-' && raw[8] == '-' &&
		digitsAtAllOtherPositions(raw[:11], 0, 5, 8)
}

func validCallingCode(digits []byte) bool {
	limit := 3
	if len(digits) < limit {
		limit = len(digits)
	}
	value := 0
	for index := 0; index < limit; index++ {
		value = value*10 + int(digits[index]-'0')
		if callingCodeValid(value) {
			return true
		}
	}
	return false
}

func callingCodeValid(value int) bool {
	switch value {
	case 1, 7, 20, 27, 30, 31, 32, 33, 34, 36, 39, 40, 41, 43, 44, 45, 46, 47, 48, 49,
		51, 52, 53, 54, 55, 56, 57, 58, 60, 61, 62, 63, 64, 65, 66, 81, 82, 84, 86, 90, 91, 92, 93, 94, 95, 98,
		211, 212, 213, 216, 218, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
		240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269,
		290, 291, 297, 298, 299, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 370, 371, 372, 373, 374, 375, 376, 377, 378, 380, 381, 382, 383, 385, 386, 387, 389,
		420, 421, 423, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 590, 591, 592, 593, 594, 595, 596, 597, 598, 599,
		670, 672, 673, 674, 675, 676, 677, 678, 679, 680, 681, 682, 683, 685, 686, 687, 688, 689, 690, 691, 692,
		800, 808, 850, 852, 853, 855, 856, 870, 878, 880, 881, 882, 883, 886, 888,
		960, 961, 962, 963, 964, 965, 966, 967, 968, 970, 971, 972, 973, 974, 975, 976, 977, 979, 992, 993, 994, 995, 996, 998:
		return true
	default:
		return false
	}
}

func scanStructuredIdentifiers(text []byte, matches []match, enabled entityMask) ([]match, error) {
	for start := 0; start < len(text); start++ {
		if !isASCIIAlphanumeric(text[start]) || !wordBoundaryBefore(text, start) {
			continue
		}
		var err error
		if isASCIILetter(text[start]) {
			if enabled.has(EntityIBAN) {
				matches, err = detectIBANAt(text, start, matches)
				if err != nil {
					return nil, err
				}
			}
			if enabled.has(EntityUKNINO) {
				matches, err = detectNINOAt(text, start, matches)
				if err != nil {
					return nil, err
				}
			}
			if enabled.has(EntitySpainDNI) {
				matches, err = detectNIEAt(text, start, matches)
				if err != nil {
					return nil, err
				}
			}
			if enabled.has(EntityItalyFiscalCode) {
				matches, err = detectItalyFiscalCodeAt(text, start, matches)
				if err != nil {
					return nil, err
				}
			}
			if enabled.has(EntitySingaporeNationalID) {
				matches, err = detectSingaporeIDAt(text, start, matches)
				if err != nil {
					return nil, err
				}
			}
			if enabled.has(EntityGermanyHealthInsurance) {
				matches, err = detectGermanyHealthInsuranceAt(text, start, matches)
				if err != nil {
					return nil, err
				}
			}
		}
		if isASCIIDigit(text[start]) {
			if enabled.has(EntityUSMedicareID) {
				matches, err = detectUSMedicareIDAt(text, start, matches)
				if err != nil {
					return nil, err
				}
			}
			if enabled.has(EntityGermanySocialSecurity) {
				matches, err = detectGermanySocialSecurityAt(text, start, matches)
				if err != nil {
					return nil, err
				}
			}
			if enabled.has(EntitySpainDNI) {
				matches, err = detectDNIAt(text, start, matches)
				if err != nil {
					return nil, err
				}
			}
			if enabled.has(EntityFinlandPersonalID) {
				matches, err = detectFinlandIDAt(text, start, matches)
				if err != nil {
					return nil, err
				}
			}
			if enabled.has(EntityChinaResidentID) {
				matches, err = detectChinaIDAt(text, start, matches)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return matches, nil
}

func detectIBANAt(text []byte, start int, matches []match) ([]match, error) {
	if start+4 > len(text) || !isASCIILetter(text[start+1]) || !isASCIIDigit(text[start+2]) || !isASCIIDigit(text[start+3]) {
		return matches, nil
	}
	first, second := text[start], text[start+1]
	if first >= 'a' {
		first -= 'a' - 'A'
	}
	if second >= 'a' {
		second -= 'a' - 'A'
	}
	expected := ibanCountryLength(first, second)
	if expected == 0 {
		return matches, nil
	}
	end, ok := compactAlphanumericEnd(text, start, expected, true)
	if !ok || !wordBoundaryAfter(text, end) || !ibanPresentationValid(text[start:end]) || !ibanValid(text[start:end]) {
		return matches, nil
	}
	return appendMatch(matches, start, end, EntityIBAN, 87)
}

func ibanPresentationValid(value []byte) bool {
	previousSpace := false
	for index, character := range value {
		if character != ' ' {
			previousSpace = false
			continue
		}
		// The country and check digits remain contiguous. Registered print
		// formats after them are not uniformly grouped in blocks of four.
		if index < 4 || index == len(value)-1 || previousSpace {
			return false
		}
		previousSpace = true
	}
	return true
}

func compactAlphanumericEnd(text []byte, start, count int, allowSpaces bool) (int, bool) {
	seen := 0
	end := start
	for end < len(text) && seen < count {
		character := text[end]
		if isASCIIAlphanumeric(character) {
			seen++
			end++
			continue
		}
		if allowSpaces && character == ' ' && seen > 0 {
			end++
			continue
		}
		return end, false
	}
	for end > start && text[end-1] == ' ' {
		end--
	}
	if seen != count || end < len(text) && isASCIIAlphanumeric(text[end]) {
		return end, false
	}
	return end, true
}

func detectNINOAt(text []byte, start int, matches []match) ([]match, error) {
	var compact [9]byte
	end, ok := compactPattern(text, start, compact[:], true)
	if !ok || !ninoValid(compact[:]) || !wordBoundaryAfter(text, end) || !hasNearbyContext(text, start, end, "nino", "national insurance") {
		return matches, nil
	}
	return appendMatch(matches, start, end, EntityUKNINO, 78)
}

func compactPattern(text []byte, start int, output []byte, allowSpaces bool) (int, bool) {
	index := start
	written := 0
	for index < len(text) && written < len(output) {
		character := text[index]
		if isASCIIAlphanumeric(character) {
			if character >= 'a' && character <= 'z' {
				character -= 'a' - 'A'
			}
			output[written] = character
			written++
			index++
			continue
		}
		if allowSpaces && character == ' ' && written > 0 {
			index++
			continue
		}
		return index, false
	}
	for index > start && text[index-1] == ' ' {
		index--
	}
	return index, written == len(output)
}

func ninoValid(value []byte) bool {
	if len(value) != 9 || !isASCIILetter(value[0]) || !isASCIILetter(value[1]) {
		return false
	}
	if containsByte([]byte("DFIQUV"), value[0]) || containsByte([]byte("DFIOQUV"), value[1]) {
		return false
	}
	for _, invalid := range []string{"BG", "GB", "NK", "KN", "TN", "NT", "ZZ"} {
		if string(value[:2]) == invalid {
			return false
		}
	}
	for _, digit := range value[2:8] {
		if !isASCIIDigit(digit) {
			return false
		}
	}
	return value[8] >= 'A' && value[8] <= 'D'
}

func containsByte(value []byte, target byte) bool {
	for _, item := range value {
		if item == target {
			return true
		}
	}
	return false
}

func detectDNIAt(text []byte, start int, matches []match) ([]match, error) {
	const checks = "TRWAGMYFPDXBNJZSQVHLCKE"
	for _, digitCount := range [...]int{8, 7} {
		digitEnd := start + digitCount
		if digitEnd >= len(text) || !allASCIIDigits(text[start:digitEnd]) {
			continue
		}
		letterAt := digitEnd
		if text[letterAt] == '-' {
			letterAt++
		}
		end := letterAt + 1
		if end > len(text) || !wordBoundaryAfter(text, end) {
			continue
		}
		letter := text[letterAt]
		if letter >= 'a' && letter <= 'z' {
			letter -= 'a' - 'A'
		}
		if isASCIILetter(letter) && checks[decimalPrefix(text[start:digitEnd], digitCount)%23] == letter && hasNearbyContext(
			text, start, end, "dni", "nif", "spanish national id", "documento nacional de identidad", "identificación",
		) {
			return appendMatch(matches, start, end, EntitySpainDNI, 78)
		}
	}
	return matches, nil
}

func detectNIEAt(text []byte, start int, matches []match) ([]match, error) {
	first := text[start]
	if first >= 'a' {
		first -= 'a' - 'A'
	}
	if first != 'X' && first != 'Y' && first != 'Z' {
		return matches, nil
	}
	digitEnd := start + 8
	if digitEnd >= len(text) || !allASCIIDigits(text[start+1:digitEnd]) {
		return matches, nil
	}
	letterAt := digitEnd
	if text[letterAt] == '-' {
		letterAt++
	}
	end := letterAt + 1
	if end > len(text) || !wordBoundaryAfter(text, end) {
		return matches, nil
	}
	number := int(first-'X')*10_000_000 + decimalPrefix(text[start+1:digitEnd], 7)
	letter := text[letterAt]
	if letter >= 'a' && letter <= 'z' {
		letter -= 'a' - 'A'
	}
	const checks = "TRWAGMYFPDXBNJZSQVHLCKE"
	if !isASCIILetter(letter) || checks[number%23] != letter || !hasNearbyContext(
		text, start, end, "nie", "extranjero", "spanish national id", "número de identificación de extranjero",
	) {
		return matches, nil
	}
	return appendMatch(matches, start, end, EntitySpainDNI, 78)
}

func detectItalyFiscalCodeAt(text []byte, start int, matches []match) ([]match, error) {
	if start+16 > len(text) || !wordBoundaryAfter(text, start+16) {
		return matches, nil
	}
	var code [16]byte
	copy(code[:], text[start:start+16])
	for index, character := range code {
		if character >= 'a' && character <= 'z' {
			code[index] = character - ('a' - 'A')
		}
	}
	if !italyFiscalCodeValid(code[:]) || !hasNearbyContext(text, start, start+16, "codice fiscale", "fiscal code") {
		return matches, nil
	}
	return appendMatch(matches, start, start+16, EntityItalyFiscalCode, 78)
}

func italyFiscalCodeValid(value []byte) bool {
	if len(value) != 16 {
		return false
	}
	for index, character := range value[:15] {
		letterExpected := index < 6 || index == 8 || index == 11
		if (letterExpected && !isASCIILetter(character)) || (!letterExpected && !italyFiscalDigit(character)) {
			return false
		}
	}
	if !isASCIILetter(value[15]) || !containsByte([]byte("ABCDEHLMPRST"), value[8]) {
		return false
	}
	month := italyFiscalMonth(value[8])
	day, ok := italyFiscalNumber(value[9:11])
	if !ok {
		return false
	}
	if day > 40 {
		day -= 40
	}
	yearSuffix, ok := italyFiscalNumber(value[6:8])
	if !ok || (!validCalendarMonthDay(1900+yearSuffix, month, day) && !validCalendarMonthDay(2000+yearSuffix, month, day)) {
		return false
	}
	const oddLetters = "BAKPLCQDREVOSFTGUHMINJWZYX"
	oddDigits := [...]int{1, 0, 5, 7, 9, 13, 15, 17, 19, 21}
	sum := 0
	for index, character := range value[:15] {
		if index%2 == 1 {
			if isASCIIDigit(character) {
				sum += int(character - '0')
			} else {
				sum += int(character - 'A')
			}
			continue
		}
		if isASCIIDigit(character) {
			sum += oddDigits[character-'0']
			continue
		}
		position := 0
		for oddLetters[position] != character {
			position++
		}
		sum += position
	}
	return byte('A'+sum%26) == value[15]
}

func italyFiscalDigit(character byte) bool {
	return isASCIIDigit(character) || containsByte([]byte("LMNPQRSTUV"), character)
}

func italyFiscalNumber(value []byte) (int, bool) {
	result := 0
	for _, character := range value {
		digit := -1
		if isASCIIDigit(character) {
			digit = int(character - '0')
		} else {
			for index, substitution := range []byte("LMNPQRSTUV") {
				if character == substitution {
					digit = index
					break
				}
			}
		}
		if digit < 0 {
			return 0, false
		}
		result = result*10 + digit
	}
	return result, true
}

func italyFiscalMonth(character byte) int {
	for index, code := range []byte("ABCDEHLMPRST") {
		if character == code {
			return index + 1
		}
	}
	return 0
}

func detectSingaporeIDAt(text []byte, start int, matches []match) ([]match, error) {
	first := text[start]
	if first >= 'a' && first <= 'z' {
		first -= 'a' - 'A'
	}
	if !containsByte([]byte("STFGM"), first) || start+9 > len(text) || !wordBoundaryAfter(text, start+9) {
		return matches, nil
	}
	var value [9]byte
	copy(value[:], text[start:start+9])
	for index, character := range value {
		if character >= 'a' && character <= 'z' {
			value[index] = character - ('a' - 'A')
		}
	}
	if !singaporeIDValid(value[:]) || !hasNearbyContext(text, start, start+9, "nric", "fin", "singapore id") {
		return matches, nil
	}
	return appendMatch(matches, start, start+9, EntitySingaporeNationalID, 78)
}

func detectGermanyHealthInsuranceAt(text []byte, start int, matches []match) ([]match, error) {
	const length = 10
	if start+length > len(text) || !wordBoundaryAfter(text, start+length) {
		return matches, nil
	}
	value := text[start : start+length]
	if !germanyHealthInsuranceValid(value) || !hasNearbyContext(
		text, start, start+length,
		"kvnr", "krankenversicherungsnummer", "krankenversichertennummer", "krankenkasse", "gesundheitskarte", "gkv", "egk",
	) {
		return matches, nil
	}
	return appendMatch(matches, start, start+length, EntityGermanyHealthInsurance, 79)
}

func detectUSMedicareIDAt(text []byte, start int, matches []match) ([]match, error) {
	for _, length := range [...]int{13, 11} {
		if start+length > len(text) || !wordBoundaryAfter(text, start+length) {
			continue
		}
		value := text[start : start+length]
		if usMedicareIDValid(value) && hasNearbyContext(text, start, start+length, "medicare", "mbi", "beneficiary", "cms", "medicaid", "hicn") {
			return appendMatch(matches, start, start+length, EntityUSMedicareID, 79)
		}
	}
	return matches, nil
}

func detectGermanySocialSecurityAt(text []byte, start int, matches []match) ([]match, error) {
	const length = 12
	if start+length > len(text) || !wordBoundaryAfter(text, start+length) {
		return matches, nil
	}
	value := text[start : start+length]
	if !germanySocialSecurityValid(value) || !hasNearbyContext(
		text, start, start+length,
		"rentenversicherungsnummer", "sozialversicherungsnummer", "rvnr", "svnr", "sv-nummer",
		"deutsche rentenversicherung", "sozialversicherungsausweis", "german social security",
	) {
		return matches, nil
	}
	return appendMatch(matches, start, start+length, EntityGermanySocialSecurity, 79)
}

func singaporeIDValid(value []byte) bool {
	if len(value) != 9 || !containsByte([]byte("STFGM"), value[0]) || !isASCIILetter(value[8]) {
		return false
	}
	weights := [...]int{2, 7, 6, 5, 4, 3, 2}
	sum := 0
	for index, weight := range weights {
		if !isASCIIDigit(value[index+1]) {
			return false
		}
		sum += int(value[index+1]-'0') * weight
	}
	var checks string
	switch value[0] {
	case 'S':
		checks = "JZIHGFEDCBA"
	case 'T':
		sum += 4
		checks = "JZIHGFEDCBA"
	case 'F':
		checks = "XWUTRQPNMLK"
	case 'G':
		sum += 4
		checks = "XWUTRQPNMLK"
	case 'M':
		sum += 3
		checks = "KLJNPQRTUWX"
	}
	return checks[sum%11] == value[8]
}

func detectFinlandIDAt(text []byte, start int, matches []match) ([]match, error) {
	if start+11 > len(text) || !wordBoundaryAfter(text, start+11) {
		return matches, nil
	}
	value := text[start : start+11]
	if !finlandIDValid(value) || !hasNearbyContext(text, start, start+11, "hetu", "henkilotunnus", "finnish personal id") {
		return matches, nil
	}
	return appendMatch(matches, start, start+11, EntityFinlandPersonalID, 78)
}

func finlandIDValid(value []byte) bool {
	if len(value) != 11 {
		return false
	}
	var normalized [11]byte
	copy(normalized[:], value)
	for index, character := range normalized {
		if character >= 'a' && character <= 'z' {
			normalized[index] = character - ('a' - 'A')
		}
	}
	value = normalized[:]
	century := 0
	switch value[6] {
	case '+':
		century = 1800
	case '-', 'Y', 'X', 'W', 'V', 'U':
		century = 1900
	case 'A', 'B', 'C', 'D', 'E', 'F':
		century = 2000
	default:
		return false
	}
	for index := 0; index < 10; index++ {
		if index != 6 && !isASCIIDigit(value[index]) {
			return false
		}
	}
	year := century + decimalPrefix(value[4:6], 2)
	month := decimalPrefix(value[2:4], 2)
	day := decimalPrefix(value[:2], 2)
	if !validCalendarMonthDay(year, month, day) {
		return false
	}
	number := decimalPrefix(value[:6], 6)*1000 + decimalPrefix(value[7:10], 3)
	check := value[10]
	if check >= 'a' {
		check -= 'a' - 'A'
	}
	const checks = "0123456789ABCDEFHJKLMNPRSTUVWXY"
	return checks[number%31] == check
}

func detectChinaIDAt(text []byte, start int, matches []match) ([]match, error) {
	if start+18 > len(text) || !wordBoundaryAfter(text, start+18) {
		return matches, nil
	}
	value := text[start : start+18]
	if !chinaResidentIDValid(value) || !hasNearbyContext(text, start, start+18, "resident id", "citizen id", "chinese id") {
		return matches, nil
	}
	return appendMatch(matches, start, start+18, EntityChinaResidentID, 78)
}
