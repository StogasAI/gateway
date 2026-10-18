// Package location holds the closed vocabulary of data locations: ISO 3166-1 alpha-2 countries,
// the regions apac, eu and europe, world, unknown, and none for content that is not stored.
package location

import "strings"

const countries = "|AD|AE|AF|AG|AI|AL|AM|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|" +
	"BA|BB|BD|BE|BF|BG|BH|BI|BJ|BL|BM|BN|BO|BQ|BR|BS|BT|BV|BW|BY|BZ|" +
	"CA|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|" +
	"DE|DJ|DK|DM|DO|DZ|EC|EE|EG|EH|ER|ES|ET|FI|FJ|FK|FM|FO|FR|" +
	"GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|" +
	"HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP|" +
	"KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|" +
	"MA|MC|MD|ME|MF|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|" +
	"NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|" +
	"QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|SS|ST|SV|SX|SY|SZ|" +
	"TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TR|TT|TV|TW|TZ|UA|UG|UM|US|UY|UZ|" +
	"VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|ZA|ZM|ZW|"

const euCountries = "|AT|BE|BG|HR|CY|CZ|DK|EE|FI|FR|DE|GR|HU|IE|IT|LV|LT|LU|MT|NL|PL|PT|RO|SK|SI|ES|SE|"

// Europe contains its EU child, so it includes Cyprus.
const europeCountries = "|AD|AL|AT|AX|BA|BE|BG|BY|CH|CY|CZ|DE|DK|EE|ES|FI|FO|FR|GB|GG|GI|GR|" +
	"HR|HU|IE|IM|IS|IT|JE|LI|LT|LU|LV|MC|MD|ME|MK|MT|NL|NO|PL|PT|RO|RS|RU|SE|SI|SJ|SK|SM|UA|VA|"

const apacCountries = "|AF|AM|AS|AU|AZ|BD|BN|BT|CC|CK|CN|CX|FJ|FM|GE|GU|HK|ID|IN|IO|JP|KG|KH|KI|KP|KR|KZ|" +
	"LA|LK|MH|MM|MN|MO|MP|MV|MY|NC|NF|NP|NR|NU|NZ|PF|PG|PH|PK|PN|PW|SB|SG|TH|TJ|TK|TL|TM|TO|TR|TV|TW|UM|UZ|VU|WF|WS|VN|"

// Country reports whether value is an assigned ISO 3166-1 alpha-2 code.
func Country(value string) bool {
	return len(value) == 2 && strings.Contains(countries, "|"+value+"|")
}

// Valid reports whether value is a location. Only storage uses none, so it needs allowNone.
func Valid(value string, allowNone bool) bool {
	switch value {
	case "world", "apac", "eu", "europe", "unknown":
		return true
	case "none":
		return allowNone
	}
	return Country(value)
}

// Within reports whether actual is at least as geographically narrow as boundary.
func Within(actual, boundary string) bool {
	if !Valid(actual, true) || !Valid(boundary, true) {
		return false
	}
	if actual == boundary || boundary == "world" || boundary == "unknown" {
		return true
	}
	if actual == "unknown" || actual == "world" || actual == "none" || boundary == "none" {
		return false
	}
	switch boundary {
	case "eu":
		return strings.Contains(euCountries, "|"+actual+"|")
	case "europe":
		return actual == "eu" || strings.Contains(europeCountries, "|"+actual+"|")
	case "apac":
		return strings.Contains(apacCountries, "|"+actual+"|")
	default:
		return false
	}
}
