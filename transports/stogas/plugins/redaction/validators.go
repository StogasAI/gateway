package redaction

func luhnValid(digits []byte) bool {
	if len(digits) == 0 || !allASCIIDigits(digits) || allEqual(digits) {
		return false
	}
	sum := 0
	double := false
	for index := len(digits) - 1; index >= 0; index-- {
		value := int(digits[index] - '0')
		if double {
			value *= 2
			if value > 9 {
				value -= 9
			}
		}
		sum += value
		double = !double
	}
	return sum%10 == 0
}

func canadaSINValid(digits []byte) bool {
	return len(digits) == 9 && allASCIIDigits(digits) && digits[0] != '0' && digits[0] != '8' && luhnValid(digits)
}

func paymentCardValid(digits []byte) bool {
	if !paymentNumberChecksumValid(digits) {
		return false
	}
	prefix2 := decimalPrefix(digits, 2)
	prefix3 := decimalPrefix(digits, 3)
	prefix4 := decimalPrefix(digits, 4)
	prefix6 := decimalPrefix(digits, 6)
	switch {
	case digits[0] == '1':
		return len(digits) == 15
	case prefix4 >= 2200 && prefix4 <= 2204:
		return len(digits) >= 16 && len(digits) <= 19
	case digits[0] == '4':
		return len(digits) == 13 || len(digits) == 16 || len(digits) == 18 || len(digits) == 19
	case prefix2 >= 51 && prefix2 <= 55:
		return len(digits) == 16
	case prefix4 >= 2221 && prefix4 <= 2720:
		return len(digits) == 16
	case prefix2 == 34 || prefix2 == 37:
		return len(digits) == 15
	case prefix4 == 6011 || prefix2 == 65 || prefix3 >= 644 && prefix3 <= 649 || prefix6 >= 622126 && prefix6 <= 622925:
		return len(digits) == 16 || len(digits) == 19
	case prefix4 >= 3528 && prefix4 <= 3589:
		return len(digits) >= 16 && len(digits) <= 19
	case prefix3 >= 300 && prefix3 <= 305 || prefix2 == 36 || prefix2 == 38 || prefix2 == 39:
		return len(digits) == 14 || len(digits) == 16 || len(digits) == 19
	case prefix2 == 50 || prefix2 >= 56 && prefix2 <= 59 || prefix2 == 63 || prefix2 >= 67 && prefix2 <= 69:
		return len(digits) >= 13 && len(digits) <= 19
	case prefix2 == 62:
		return len(digits) >= 16 && len(digits) <= 19
	case prefix3 >= 810 && prefix3 <= 817:
		return len(digits) >= 14 && len(digits) <= 19
	case prefix4 == 9792:
		return len(digits) == 16
	default:
		return false
	}
}

func paymentNumberChecksumValid(digits []byte) bool {
	return len(digits) >= 13 && len(digits) <= 19 && luhnValid(digits)
}

func decimalPrefix(digits []byte, count int) int {
	if count < 1 || len(digits) < count {
		return -1
	}
	value := 0
	for _, digit := range digits[:count] {
		if !isASCIIDigit(digit) {
			return -1
		}
		value = value*10 + int(digit-'0')
	}
	return value
}

func allASCIIDigits(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, character := range value {
		if !isASCIIDigit(character) {
			return false
		}
	}
	return true
}

func ibanValid(value []byte) bool {
	var compact [34]byte
	length := 0
	for _, character := range value {
		if character == ' ' {
			continue
		}
		if length == len(compact) || !isASCIIAlphanumeric(character) {
			return false
		}
		if character >= 'a' && character <= 'z' {
			character -= 'a' - 'A'
		}
		compact[length] = character
		length++
	}
	if length < 15 || length != ibanCountryLength(compact[0], compact[1]) || !isASCIILetter(compact[0]) || !isASCIILetter(compact[1]) || !isASCIIDigit(compact[2]) || !isASCIIDigit(compact[3]) {
		return false
	}
	remainder := 0
	for offset := 0; offset < length; offset++ {
		character := compact[(offset+4)%length]
		if isASCIIDigit(character) {
			remainder = (remainder*10 + int(character-'0')) % 97
			continue
		}
		if !isASCIILetter(character) {
			return false
		}
		value := int(character-'A') + 10
		remainder = (remainder*100 + value) % 97
	}
	return remainder == 1
}

func ibanCountryLength(first, second byte) int {
	code := uint16(first)<<8 | uint16(second)
	switch code {
	case 'A'<<8 | 'L':
		return 28
	case 'A'<<8 | 'D':
		return 24
	case 'A'<<8 | 'T':
		return 20
	case 'A'<<8 | 'Z':
		return 28
	case 'B'<<8 | 'H':
		return 22
	case 'B'<<8 | 'I':
		return 27
	case 'B'<<8 | 'Y':
		return 28
	case 'B'<<8 | 'E':
		return 16
	case 'B'<<8 | 'A':
		return 20
	case 'B'<<8 | 'R':
		return 29
	case 'B'<<8 | 'G':
		return 22
	case 'C'<<8 | 'R':
		return 22
	case 'H'<<8 | 'R':
		return 21
	case 'C'<<8 | 'Y':
		return 28
	case 'C'<<8 | 'Z':
		return 24
	case 'D'<<8 | 'K':
		return 18
	case 'D'<<8 | 'J':
		return 27
	case 'D'<<8 | 'O':
		return 28
	case 'E'<<8 | 'G':
		return 29
	case 'S'<<8 | 'V':
		return 28
	case 'E'<<8 | 'E':
		return 20
	case 'F'<<8 | 'O':
		return 18
	case 'F'<<8 | 'K':
		return 18
	case 'F'<<8 | 'I':
		return 18
	case 'F'<<8 | 'R':
		return 27
	case 'G'<<8 | 'E':
		return 22
	case 'D'<<8 | 'E':
		return 22
	case 'G'<<8 | 'I':
		return 23
	case 'G'<<8 | 'R':
		return 27
	case 'G'<<8 | 'L':
		return 18
	case 'G'<<8 | 'T':
		return 28
	case 'H'<<8 | 'U':
		return 28
	case 'H'<<8 | 'N':
		return 28
	case 'I'<<8 | 'S':
		return 26
	case 'I'<<8 | 'Q':
		return 23
	case 'I'<<8 | 'E':
		return 22
	case 'I'<<8 | 'L':
		return 23
	case 'I'<<8 | 'T':
		return 27
	case 'J'<<8 | 'O':
		return 30
	case 'K'<<8 | 'Z':
		return 20
	case 'X'<<8 | 'K':
		return 20
	case 'K'<<8 | 'W':
		return 30
	case 'L'<<8 | 'V':
		return 21
	case 'L'<<8 | 'B':
		return 28
	case 'L'<<8 | 'I':
		return 21
	case 'L'<<8 | 'Y':
		return 25
	case 'L'<<8 | 'T':
		return 20
	case 'L'<<8 | 'U':
		return 20
	case 'M'<<8 | 'T':
		return 31
	case 'M'<<8 | 'R':
		return 27
	case 'M'<<8 | 'U':
		return 30
	case 'M'<<8 | 'D':
		return 24
	case 'M'<<8 | 'C':
		return 27
	case 'M'<<8 | 'E':
		return 22
	case 'M'<<8 | 'N':
		return 20
	case 'N'<<8 | 'L':
		return 18
	case 'M'<<8 | 'K':
		return 19
	case 'N'<<8 | 'O':
		return 15
	case 'N'<<8 | 'I':
		return 28
	case 'O'<<8 | 'M':
		return 23
	case 'P'<<8 | 'K':
		return 24
	case 'P'<<8 | 'S':
		return 29
	case 'P'<<8 | 'L':
		return 28
	case 'P'<<8 | 'T':
		return 25
	case 'Q'<<8 | 'A':
		return 29
	case 'R'<<8 | 'O':
		return 24
	case 'R'<<8 | 'U':
		return 33
	case 'L'<<8 | 'C':
		return 32
	case 'S'<<8 | 'M':
		return 27
	case 'S'<<8 | 'O':
		return 23
	case 'S'<<8 | 'T':
		return 25
	case 'S'<<8 | 'A':
		return 24
	case 'R'<<8 | 'S':
		return 22
	case 'S'<<8 | 'C':
		return 31
	case 'S'<<8 | 'K':
		return 24
	case 'S'<<8 | 'I':
		return 19
	case 'E'<<8 | 'S':
		return 24
	case 'S'<<8 | 'D':
		return 18
	case 'S'<<8 | 'E':
		return 24
	case 'C'<<8 | 'H':
		return 21
	case 'T'<<8 | 'L':
		return 23
	case 'T'<<8 | 'N':
		return 24
	case 'T'<<8 | 'R':
		return 26
	case 'U'<<8 | 'A':
		return 29
	case 'A'<<8 | 'E':
		return 23
	case 'G'<<8 | 'B':
		return 22
	case 'V'<<8 | 'A':
		return 22
	case 'V'<<8 | 'G':
		return 24
	case 'Y'<<8 | 'E':
		return 30
	default:
		return 0
	}
}

func usSSNValid(digits []byte) bool {
	if len(digits) != 9 || !allASCIIDigits(digits) || allEqual(digits) {
		return false
	}
	area := decimalPrefix(digits, 3)
	group := decimalPrefix(digits[3:], 2)
	serial := decimalPrefix(digits[5:], 4)
	if area == 0 || area == 666 || area >= 900 || group == 0 || serial == 0 {
		return false
	}
	return !equalFoldASCII(digits, "078051120") && !equalFoldASCII(digits, "123456789") &&
		!equalFoldASCII(digits, "987654320")
}

func usITINValid(digits []byte) bool {
	if len(digits) != 9 || !allASCIIDigits(digits) || digits[0] != '9' || allEqual(digits) {
		return false
	}
	group := decimalPrefix(digits[3:], 2)
	serial := decimalPrefix(digits[5:], 4)
	return ((group >= 50 && group <= 65) || (group >= 70 && group <= 88) || (group >= 90 && group <= 92) || (group >= 94 && group <= 99)) && serial != 0
}

func abaRoutingValid(digits []byte) bool {
	if len(digits) != 9 || !allASCIIDigits(digits) || allEqual(digits) {
		return false
	}
	prefix := decimalPrefix(digits, 2)
	if !((prefix >= 0 && prefix <= 12) || (prefix >= 21 && prefix <= 32) ||
		(prefix >= 61 && prefix <= 72) || prefix == 80) {
		return false
	}
	sum := 3*int(digits[0]+digits[3]+digits[6]-3*'0') + 7*int(digits[1]+digits[4]+digits[7]-3*'0') + int(digits[2]+digits[5]+digits[8]-3*'0')
	return sum%10 == 0
}

func nhsNumberValid(digits []byte) bool {
	if len(digits) != 10 || !allASCIIDigits(digits) || allEqual(digits) {
		return false
	}
	sum := 0
	for index := 0; index < 9; index++ {
		sum += int(digits[index]-'0') * (10 - index)
	}
	check := 11 - sum%11
	if check == 11 {
		check = 0
	}
	return check != 10 && check == int(digits[9]-'0')
}

func usNPIValid(digits []byte) bool {
	if len(digits) != 10 || !allASCIIDigits(digits) || (digits[0] != '1' && digits[0] != '2') || allEqual(digits[:9]) {
		return false
	}
	var prefixed [15]byte
	copy(prefixed[:], "80840")
	copy(prefixed[5:], digits)
	return luhnValid(prefixed[:])
}

func australiaTFNValid(digits []byte) bool {
	if len(digits) != 9 || !allASCIIDigits(digits) || allEqual(digits) {
		return false
	}
	weights := [...]int{1, 4, 3, 7, 5, 8, 6, 9, 10}
	sum := 0
	for index, weight := range weights {
		sum += int(digits[index]-'0') * weight
	}
	return sum%11 == 0
}

func australiaABNValid(digits []byte) bool {
	if len(digits) != 11 || !allASCIIDigits(digits) || allEqual(digits) || digits[0] == '0' {
		return false
	}
	weights := [...]int{10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19}
	sum := (int(digits[0]-'0') - 1) * weights[0]
	for index := 1; index < len(weights); index++ {
		sum += int(digits[index]-'0') * weights[index]
	}
	return sum%89 == 0
}

func australiaACNValid(digits []byte) bool {
	if len(digits) != 9 || !allASCIIDigits(digits) || allEqual(digits) {
		return false
	}
	weights := [...]int{8, 7, 6, 5, 4, 3, 2, 1}
	sum := 0
	for index, weight := range weights {
		sum += int(digits[index]-'0') * weight
	}
	return (10-sum%10)%10 == int(digits[8]-'0')
}

func australiaMedicareValid(digits []byte) bool {
	if len(digits) != 10 || !allASCIIDigits(digits) || digits[0] < '2' || digits[0] > '6' || digits[9] == '0' {
		return false
	}
	weights := [...]int{1, 3, 7, 9, 1, 3, 7, 9}
	sum := 0
	for index, weight := range weights {
		sum += int(digits[index]-'0') * weight
	}
	return sum%10 == int(digits[8]-'0')
}

func turkeyNationalIDValid(digits []byte) bool {
	if len(digits) != 11 || !allASCIIDigits(digits) || digits[0] == '0' || allEqual(digits) {
		return false
	}
	odd := 0
	for index := 0; index < 9; index += 2 {
		odd += int(digits[index] - '0')
	}
	even := 0
	for index := 1; index < 8; index += 2 {
		even += int(digits[index] - '0')
	}
	tenth := (odd*7 - even) % 10
	if tenth < 0 {
		tenth += 10
	}
	if tenth != int(digits[9]-'0') {
		return false
	}
	sum := 0
	for _, digit := range digits[:10] {
		sum += int(digit - '0')
	}
	return sum%10 == int(digits[10]-'0')
}

func germanyTaxIDValid(digits []byte) bool {
	if len(digits) != 11 || !allASCIIDigits(digits) || digits[0] == '0' {
		return false
	}
	var counts [10]uint8
	for _, digit := range digits[:10] {
		counts[digit-'0']++
		if counts[digit-'0'] > 3 {
			return false
		}
	}
	product := 10
	for _, digit := range digits[:10] {
		total := (int(digit-'0') + product) % 10
		if total == 0 {
			total = 10
		}
		product = total * 2 % 11
	}
	check := 11 - product
	if check == 10 {
		check = 0
	}
	return check == int(digits[10]-'0')
}

func swedenPersonalIDValid(raw, digits []byte) bool {
	if len(digits) != 10 && len(digits) != 12 || !allASCIIDigits(digits) {
		return false
	}
	separatorAt := len(digits) - 4
	if len(raw) != len(digits) && (len(raw) != len(digits)+1 || raw[separatorAt] != '-' && raw[separatorAt] != '+') {
		return false
	}
	number := digits[len(digits)-10:]
	month := decimalPrefix(number[2:], 2)
	day := decimalPrefix(number[4:], 2)
	if day >= 61 && day <= 91 {
		day -= 60
	}
	dateValid := false
	if len(digits) == 12 {
		dateValid = validCalendarMonthDay(decimalPrefix(digits, 4), month, day)
	} else {
		year := decimalPrefix(number, 2)
		dateValid = validCalendarMonthDay(1900+year, month, day) || validCalendarMonthDay(2000+year, month, day)
	}
	return dateValid && luhnValid(number)
}

func koreaBusinessNumberValid(digits []byte) bool {
	if len(digits) != 10 || !allASCIIDigits(digits) || allEqual(digits) {
		return false
	}
	weights := [...]int{1, 3, 7, 1, 3, 7, 1, 3}
	sum := 0
	for index, weight := range weights {
		sum += int(digits[index]-'0') * weight
	}
	last := int(digits[8]-'0') * 5
	sum += last + last/10
	return (10-sum%10)%10 == int(digits[9]-'0')
}

func italyVATValid(digits []byte) bool {
	if len(digits) != 11 || !allASCIIDigits(digits) || allEqual(digits) {
		return false
	}
	sum := 0
	for index := 0; index < 10; index++ {
		value := int(digits[index] - '0')
		if index%2 == 1 {
			value *= 2
			if value > 9 {
				value -= 9
			}
		}
		sum += value
	}
	return (10-sum%10)%10 == int(digits[10]-'0')
}

func germanyHealthInsuranceValid(value []byte) bool {
	if len(value) != 10 || !isASCIILetter(value[0]) || !allASCIIDigits(value[1:]) {
		return false
	}
	letter := lowerASCII(value[0]) - 'a' + 1
	var effective [10]byte
	effective[0] = '0' + letter/10
	effective[1] = '0' + letter%10
	copy(effective[2:], value[1:9])
	sum := 0
	for index, digit := range effective {
		product := int(digit - '0')
		if index%2 == 1 {
			product *= 2
			if product > 9 {
				product -= 9
			}
		}
		sum += product
	}
	return sum%10 == int(value[9]-'0')
}

func usMedicareIDValid(value []byte) bool {
	var compact [11]byte
	position := 0
	for index, character := range value {
		if (index == 4 || index == 8) && len(value) == 13 {
			if character != '-' {
				return false
			}
			continue
		}
		if position == len(compact) || !isASCIIAlphanumeric(character) {
			return false
		}
		if character >= 'a' && character <= 'z' {
			character -= 'a' - 'A'
		}
		compact[position] = character
		position++
	}
	if position != len(compact) {
		return false
	}
	for _, index := range [...]int{0, 3, 6, 9, 10} {
		if !isASCIIDigit(compact[index]) {
			return false
		}
	}
	for _, index := range [...]int{1, 4, 7, 8} {
		if !medicareLetter(compact[index]) {
			return false
		}
	}
	return (isASCIIDigit(compact[2]) || medicareLetter(compact[2])) &&
		(isASCIIDigit(compact[5]) || medicareLetter(compact[5]))
}

func germanySocialSecurityValid(value []byte) bool {
	if len(value) != 12 || !allASCIIDigits(value[:8]) || !isASCIILetter(value[8]) ||
		!allASCIIDigits(value[9:]) || decimalPrefix(value, 2) == 0 {
		return false
	}
	day := decimalPrefix(value[2:], 2)
	if day >= 51 && day <= 81 {
		day -= 50
	} else if day < 1 || day > 31 {
		return false
	}
	month := decimalPrefix(value[4:], 2)
	year := decimalPrefix(value[6:], 2)
	if !validCalendarMonthDay(1900+year, month, day) && !validCalendarMonthDay(2000+year, month, day) {
		return false
	}

	letter := lowerASCII(value[8]) - 'a' + 1
	var effective [12]byte
	copy(effective[:8], value[:8])
	effective[8] = '0' + letter/10
	effective[9] = '0' + letter%10
	copy(effective[10:], value[9:11])
	weights := [...]int{2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1}
	total := 0
	for index, digit := range effective {
		product := int(digit-'0') * weights[index]
		total += product/10 + product%10
	}
	return total%10 == int(value[11]-'0')
}

func medicareLetter(value byte) bool {
	return value >= 'A' && value <= 'Z' && !containsByte([]byte("SLOIBZ"), value)
}

var verhoeffD = [10][10]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6}, {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4}, {9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

var verhoeffP = [8][10]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2}, {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

func aadhaarValid(digits []byte) bool {
	return len(digits) == 12 && allASCIIDigits(digits) && digits[0] >= '2' && !allEqual(digits) && verhoeffValid(digits)
}

func nigeriaNINValid(digits []byte) bool {
	return len(digits) == 11 && allASCIIDigits(digits) && !allEqual(digits) && verhoeffValid(digits)
}

func verhoeffValid(digits []byte) bool {
	if len(digits) == 0 || !allASCIIDigits(digits) {
		return false
	}
	checksum := uint8(0)
	for offset := 0; offset < len(digits); offset++ {
		digit := digits[len(digits)-1-offset] - '0'
		checksum = verhoeffD[checksum][verhoeffP[offset%8][digit]]
	}
	return checksum == 0
}

func brazilCPFValid(digits []byte) bool {
	if len(digits) != 11 || !allASCIIDigits(digits) || allEqual(digits) {
		return false
	}
	for checkIndex := 9; checkIndex <= 10; checkIndex++ {
		sum := 0
		for index := 0; index < checkIndex; index++ {
			sum += int(digits[index]-'0') * (checkIndex + 1 - index)
		}
		check := (sum * 10) % 11
		if check == 10 {
			check = 0
		}
		if check != int(digits[checkIndex]-'0') {
			return false
		}
	}
	return true
}

func brazilCNPJValid(digits []byte) bool {
	if len(digits) != 14 || !allASCIIDigits(digits) || allEqual(digits) {
		return false
	}
	firstWeights := [...]int{5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
	secondWeights := [...]int{6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
	return brazilMod11Check(digits, firstWeights[:], 12) && brazilMod11Check(digits, secondWeights[:], 13)
}

func brazilMod11Check(digits []byte, weights []int, checkIndex int) bool {
	sum := 0
	for index, weight := range weights {
		sum += int(digits[index]-'0') * weight
	}
	check := 11 - sum%11
	if check >= 10 {
		check = 0
	}
	return check == int(digits[checkIndex]-'0')
}

func peselValid(digits []byte) bool {
	if len(digits) != 11 || !allASCIIDigits(digits) || allEqual(digits) {
		return false
	}
	weights := [...]int{1, 3, 7, 9, 1, 3, 7, 9, 1, 3}
	sum := 0
	for index, weight := range weights {
		sum += int(digits[index]-'0') * weight
	}
	if (10-sum%10)%10 != int(digits[10]-'0') {
		return false
	}
	year := 1900 + int(digits[0]-'0')*10 + int(digits[1]-'0')
	month := int(digits[2]-'0')*10 + int(digits[3]-'0')
	switch {
	case month >= 81 && month <= 92:
		month -= 80
		year -= 100
	case month >= 61 && month <= 72:
		month -= 60
		year += 300
	case month >= 41 && month <= 52:
		month -= 40
		year += 200
	case month >= 21 && month <= 32:
		month -= 20
		year += 100
	}
	day := int(digits[4]-'0')*10 + int(digits[5]-'0')
	return validCalendarMonthDay(year, month, day)
}

func koreaRRNValid(digits []byte) bool {
	if !koreaRegistrationStructureValid(digits) {
		return false
	}
	weights := [...]int{2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5}
	sum := 0
	for index, weight := range weights {
		sum += int(digits[index]-'0') * weight
	}
	base := 11
	if digits[6] >= '5' {
		base = 13
	}
	return (base-sum%11)%10 == int(digits[12]-'0')
}

func koreaRegistrationStructureValid(digits []byte) bool {
	if len(digits) != 13 || !allASCIIDigits(digits) || digits[6] < '1' || digits[6] > '8' {
		return false
	}
	century := 1900
	if digits[6] == '3' || digits[6] == '4' || digits[6] == '7' || digits[6] == '8' {
		century = 2000
	}
	return validYYMMDD(digits[:6], century)
}

func thailandIDValid(digits []byte) bool {
	if len(digits) != 13 || !allASCIIDigits(digits) || digits[0] == '0' || digits[1] == '0' || allEqual(digits) {
		return false
	}
	province := int(digits[1]-'0')*10 + int(digits[2]-'0')
	switch province {
	case 28, 29, 59, 68, 69, 78, 79, 87, 88, 89, 97, 98, 99:
		return false
	}
	sum := 0
	for index := 0; index < 12; index++ {
		sum += int(digits[index]-'0') * (13 - index)
	}
	return (11-sum%11)%10 == int(digits[12]-'0')
}

func chinaResidentIDValid(value []byte) bool {
	if len(value) != 18 || !allASCIIDigits(value[:17]) || !chinaProvinceCodeValid(value[:2]) ||
		(value[14] == '0' && value[15] == '0' && value[16] == '0') || !validYYYYMMDD(value[6:14]) {
		return false
	}
	weights := [...]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	checks := "10X98765432"
	sum := 0
	for index, weight := range weights {
		sum += int(value[index]-'0') * weight
	}
	last := value[17]
	if last == 'x' {
		last = 'X'
	}
	return checks[sum%11] == last
}

func chinaProvinceCodeValid(code []byte) bool {
	if len(code) != 2 || !allASCIIDigits(code) {
		return false
	}
	province := decimalPrefix(code, 2)
	return province >= 11 && province <= 15 || province >= 21 && province <= 23 ||
		province >= 31 && province <= 37 || province >= 41 && province <= 46 ||
		province >= 50 && province <= 54 || province >= 61 && province <= 65 ||
		province == 71 || province == 81 || province == 82
}

func israelIDValid(digits []byte) bool {
	if len(digits) != 9 || !allASCIIDigits(digits) || allEqual(digits) {
		return false
	}
	sum := 0
	for index, digit := range digits {
		value := int(digit - '0')
		if index%2 == 1 {
			value *= 2
			if value > 9 {
				value -= 9
			}
		}
		sum += value
	}
	return sum%10 == 0
}

func southAfricaIDValid(digits []byte) bool {
	if len(digits) != 13 || !allASCIIDigits(digits) || digits[10] < '0' || digits[10] > '2' || digits[11] < '8' || digits[11] > '9' {
		return false
	}
	if !validYYMMDD(digits[:6], 1900) && !validYYMMDD(digits[:6], 2000) {
		return false
	}
	return luhnValid(digits)
}

func validYYMMDD(yymmdd []byte, century int) bool {
	if len(yymmdd) != 6 || !allASCIIDigits(yymmdd) {
		return false
	}
	year := century + int(yymmdd[0]-'0')*10 + int(yymmdd[1]-'0')
	month := int(yymmdd[2]-'0')*10 + int(yymmdd[3]-'0')
	day := int(yymmdd[4]-'0')*10 + int(yymmdd[5]-'0')
	return validCalendarMonthDay(year, month, day)
}

func validYYYYMMDD(yyyymmdd []byte) bool {
	if len(yyyymmdd) != 8 || !allASCIIDigits(yyyymmdd) {
		return false
	}
	year := decimalPrefix(yyyymmdd, 4)
	month := decimalPrefix(yyyymmdd[4:], 2)
	day := decimalPrefix(yyyymmdd[6:], 2)
	return year >= 1800 && year <= 2199 && validCalendarMonthDay(year, month, day)
}

func validCalendarMonthDay(year, month, day int) bool {
	if month < 1 || month > 12 || day < 1 {
		return false
	}
	days := [...]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if month == 2 && (year%400 == 0 || year%4 == 0 && year%100 != 0) {
		return day <= 29
	}
	return day <= days[month-1]
}
