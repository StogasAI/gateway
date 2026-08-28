package redaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestStructuredPIIRedaction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		text        string
		placeholder string
	}{
		{name: "email", text: "Contact Jane.Doe+legal@acme-corp.co.uk now", placeholder: "<EMAIL_ADDRESS>"},
		{name: "email before punctuation", text: "Contact alice@corp.io.", placeholder: "<EMAIL_ADDRESS>"},
		{name: "North American phone", text: "Call (415) 555-2671 today", placeholder: "<PHONE_NUMBER>"},
		{name: "dotted North American phone", text: "Call 415.555.2671 today", placeholder: "<PHONE_NUMBER>"},
		{name: "country-prefixed North American phone", text: "Call +1 415-555-2671 today", placeholder: "<PHONE_NUMBER>"},
		{name: "international phone", text: "Call +44 20 7946 0958 today", placeholder: "<PHONE_NUMBER>"},
		{name: "payment card", text: "Card 4532 0151 1283 0366", placeholder: "<PAYMENT_CARD>"},
		{name: "contextual payment number", text: "Credit card number 123456789012347", placeholder: "<PAYMENT_CARD>"},
		{name: "IBAN", text: "Send to GB82 WEST 1234 5698 7654 32", placeholder: "<IBAN>"},
		{name: "Belarus IBAN", text: "Send to BY13 NBRB 3600 9000 0000 2Z00 AB00", placeholder: "<IBAN>"},
		{name: "Burundi registered IBAN grouping", text: "Send to BI42 10000 10001 00003320451 81", placeholder: "<IBAN>"},
		{name: "US SSN", text: "SSN 856-45-6789", placeholder: "<US_SSN>"},
		{name: "US ITIN", text: "ITIN 900-70-0001", placeholder: "<US_ITIN>"},
		{name: "US ITIN 50 range", text: "ITIN 911-53-1234", placeholder: "<US_ITIN>"},
		{name: "US routing number", text: "ABA routing number 021000021", placeholder: "<US_ROUTING_NUMBER>"},
		{name: "UK NHS number", text: "NHS number 943 476 5919", placeholder: "<UK_NHS_NUMBER>"},
		{name: "UK NINO", text: "National Insurance AB 12 34 56 C", placeholder: "<UK_NATIONAL_INSURANCE_NUMBER>"},
		{name: "Canada SIN", text: "Canadian SIN 130 692 544", placeholder: "<CA_SOCIAL_INSURANCE_NUMBER>"},
		{name: "Australia TFN", text: "TFN 123 456 782", placeholder: "<AU_TAX_FILE_NUMBER>"},
		{name: "Australia ABN", text: "ABN 51 824 753 556", placeholder: "<AU_BUSINESS_NUMBER>"},
		{name: "Australia ACN", text: "ACN 004 085 616", placeholder: "<AU_COMPANY_NUMBER>"},
		{name: "Australia Medicare", text: "Medicare 2123 45670 1", placeholder: "<AU_MEDICARE_NUMBER>"},
		{name: "India Aadhaar", text: "Aadhaar 9999 9999 0019", placeholder: "<IN_AADHAAR_NUMBER>"},
		{name: "India Aadhaar colon form", text: "UIDAI 9999:9999:0019", placeholder: "<IN_AADHAAR_NUMBER>"},
		{name: "Brazil CPF", text: "CPF 529.982.247-25", placeholder: "<BR_CPF>"},
		{name: "Brazil CNPJ", text: "CNPJ 04.252.011/0001-10", placeholder: "<BR_CNPJ>"},
		{name: "Spain DNI", text: "DNI 12345678Z", placeholder: "<ES_NATIONAL_ID>"},
		{name: "Spain short DNI", text: "NIF 1234567-L", placeholder: "<ES_NATIONAL_ID>"},
		{name: "Spain NIE", text: "NIE X1234567L", placeholder: "<ES_NATIONAL_ID>"},
		{name: "Spain hyphenated NIE", text: "NIE y1234567-x", placeholder: "<ES_NATIONAL_ID>"},
		{name: "Italy fiscal code", text: "Codice fiscale RSSMRA85T10A562S", placeholder: "<IT_FISCAL_CODE>"},
		{name: "Italy synthetic fiscal code", text: "Codice fiscale AAAAAA00B11C333Y", placeholder: "<IT_FISCAL_CODE>"},
		{name: "Poland PESEL", text: "PESEL 44051401458", placeholder: "<PL_PESEL>"},
		{name: "Korea RRN", text: "RRN 900101-1234568", placeholder: "<KR_RESIDENT_NUMBER>"},
		{name: "Korea randomized RRN", text: "Korean RRN 960121-1234567", placeholder: "<KR_RESIDENT_NUMBER>"},
		{name: "Korea foreigner number", text: "Korean FRN 911124-5678906", placeholder: "<KR_RESIDENT_NUMBER>"},
		{name: "Finland personal ID", text: "HETU 131052-308T", placeholder: "<FI_PERSONAL_ID>"},
		{name: "Finland modern separator", text: "HETU 010594Y9032", placeholder: "<FI_PERSONAL_ID>"},
		{name: "Thailand national ID", text: "Thai national ID 1-2345-67890-12-1", placeholder: "<TH_NATIONAL_ID>"},
		{name: "Singapore NRIC", text: "NRIC S1234567D", placeholder: "<SG_NATIONAL_ID>"},
		{name: "China resident ID", text: "Chinese resident ID 11010519491231002X", placeholder: "<CN_RESIDENT_ID>"},
		{name: "Israel national ID", text: "Israeli ID 123456782", placeholder: "<IL_NATIONAL_ID>"},
		{name: "South Africa ID", text: "South African ID 8001015009087", placeholder: "<ZA_NATIONAL_ID>"},
		{name: "South Africa refugee ID", text: "South African ID 0001015002288", placeholder: "<ZA_NATIONAL_ID>"},
		{name: "Turkey national ID", text: "TCKN 10000000146", placeholder: "<TR_NATIONAL_ID>"},
		{name: "Germany tax ID", text: "Steuer-ID 12345678903", placeholder: "<DE_TAX_ID>"},
		{name: "Sweden personal ID", text: "Personnummer 871220-2384", placeholder: "<SE_PERSONAL_ID>"},
		{name: "Sweden long personal ID", text: "Svenskt personnummer 198712202384", placeholder: "<SE_PERSONAL_ID>"},
		{name: "US NPI", text: "NPI 1234567893", placeholder: "<US_NPI>"},
		{name: "Korea business number", text: "Korean BRN 104-86-56659", placeholder: "<KR_BUSINESS_REGISTRATION_NUMBER>"},
		{name: "Italy VAT", text: "Partita IVA 01333550323", placeholder: "<IT_VAT_NUMBER>"},
		{name: "Nigeria NIN", text: "NIMC NIN 12345678902", placeholder: "<NG_NATIONAL_ID>"},
		{name: "US Medicare beneficiary ID", text: "Medicare MBI 1EG4-TE5-MK73", placeholder: "<US_MEDICARE_ID>"},
		{name: "Germany health insurance ID", text: "KVNR A123456780", placeholder: "<DE_HEALTH_INSURANCE_ID>"},
		{name: "Germany social security ID", text: "RVNR 15070649C103", placeholder: "<DE_SOCIAL_SECURITY_NUMBER>"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			redactor := New()
			out, changed, err := redactor.redactBytes([]byte(test.text))
			if err != nil {
				t.Fatal(err)
			}
			if !changed || !bytes.Contains(out, []byte(test.placeholder)) {
				t.Fatalf("redaction = %q, want %s", out, test.placeholder)
			}
			if redactor.Summary().ItemsRedacted != 1 {
				t.Fatalf("items_redacted = %d, want 1", redactor.Summary().ItemsRedacted)
			}
		})
	}
}

func TestSecretRedaction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		text        string
		placeholder string
	}{
		{name: "AWS access key", text: "AKIA7EXAMPLE9STOGAS1", placeholder: "<VENDOR_TOKEN>"},
		{name: "GitHub token", text: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", placeholder: "<VENDOR_TOKEN>"},
		{name: "OpenAI token", text: "sk-proj-AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789", placeholder: "<VENDOR_TOKEN>"},
		{name: "Slack webhook", text: "https://hooks.slack.com/" + "services/T0A1B2C3D/B4D5E6F7G/AbCdEf0123456789AbCdEf01", placeholder: "<VENDOR_TOKEN>"},
		{name: "SendGrid token", text: "SG." + "abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq", placeholder: "<VENDOR_TOKEN>"},
		{name: "JWT", text: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", placeholder: "<JSON_WEB_TOKEN>"},
		{name: "database URL", text: "postgresql://app:Sup3rSecret!@db.internal:5432/stogas", placeholder: "<DATABASE_URL>"},
		{name: "Redis password URL", text: "redis://:Sup3rSecret!@cache.internal:6379/0", placeholder: "<DATABASE_URL>"},
		{name: "JSON password", text: `{"password":"Sup3rSecret!"}`, placeholder: "<CREDENTIAL>"},
		{name: "simple explicit password", text: `{"password":"huntertwo"}`, placeholder: "<CREDENTIAL>"},
		{name: "weak explicit password", text: `{"password":"aaaaaa"}`, placeholder: "<CREDENTIAL>"},
		{name: "environment secret", text: "CLIENT_SECRET=AbCdEf0123456789!", placeholder: "<CREDENTIAL>"},
		{name: "strong UUID secret", text: "CLIENT_SECRET=550e8400-e29b-41d4-a716-446655440000", placeholder: "<CREDENTIAL>"},
		{name: "bearer", text: "Authorization: Bearer AbCdEf0123456789-_", placeholder: "<CREDENTIAL>"},
		{name: "basic", text: "Authorization: Basic dXNlcjpTdXBlclNlY3JldDEh", placeholder: "<CREDENTIAL>"},
		{name: "private key", text: "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----", placeholder: "<PRIVATE_KEY>"},
		{name: "camel-case API key", text: "serviceApiKey=AbCdEf0123456789!", placeholder: "<CREDENTIAL>"},
		{name: "namespaced API key", text: "MY_SERVICE_API_KEY=AbCdEf0123456789!", placeholder: "<CREDENTIAL>"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			redactor := New()
			out, changed, err := redactor.redactBytes([]byte(test.text))
			if err != nil {
				t.Fatal(err)
			}
			if !changed || !bytes.Contains(out, []byte(test.placeholder)) {
				t.Fatalf("redaction = %q, want %s", out, test.placeholder)
			}
			if bytes.Contains(out, []byte("Sup3rSecret")) {
				t.Fatalf("secret remained in output: %q", out)
			}
		})
	}
}

func TestKnownSecretPrefixShapes(t *testing.T) {
	t.Parallel()
	githubToken := "github_pat_" + strings.Repeat("A1b2C3d4", 2) + "E5f6G7_" + strings.Repeat("H8i9J0k1", 7) + "L2m"
	tests := []string{
		"A3-ABC123-ABCDEFGHIJK-ABCDE-FGHIJ-KLMNO",
		"bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t",
		githubToken,
		"glpat-Ab1Cd2Ef3Gh4Jk5Lm6Np7Qr8Stu.ab1234567",
		"glcbt-Ab1_" + strings.Repeat("A1", 10),
		"hf_" + strings.Repeat("Ab", 17),
		"dapi" + strings.Repeat("a1", 16),
		"dapi" + strings.Repeat("a1", 16) + "-2",
		"dop_v1_" + strings.Repeat("a1", 32),
		"ntn_12345678901" + strings.Repeat("A1", 17) + "A",
		"pplx-" + strings.Repeat("A1", 24),
		"AIza" + strings.Repeat("A1", 17) + "Z",
		"SK" + strings.Repeat("a1", 16),
		"shpat_" + strings.Repeat("a1", 16),
		"lin_api_" + strings.Repeat("A1", 20),
		"ATATT3" + strings.Repeat("A1", 93),
		"AGE-SECRET-KEY-1" + strings.Repeat("QP", 29),
		"123456789:Ab1C2d3E4f5G6h7I8j9K0l1M2n3O4p5Q6r7",
		"pypi-AgEIcHlwaS5vcmc" + strings.Repeat("A1", 25),
		"dp.pt." + strings.Repeat("a1B2c3D4e5", 4) + "a1B",
		"ops_eyJ" + strings.Repeat("Ab3+/Cd9", 32),
		"pscale_tkn_" + strings.Repeat("A1b2C3d4", 4),
		"pscale_oauth_" + strings.Repeat("A1b2C3d4", 4),
		"pscale_pw_" + strings.Repeat("A1b2C3d4", 4),
		"pul-" + strings.Repeat("0123456789abcdef", 2) + "01234567",
		"sntryu_" + strings.Repeat("0123456789abcdef", 4),
		"GR1348941" + strings.Repeat("A1b2C3d4", 2) + "Z9x7",
		"sk-svcacct-" + strings.Repeat("A1b2C3d4", 5),
		"sk-admin-" + strings.Repeat("A1b2C3d4", 5),
		"sk_prod_" + strings.Repeat("A1b2C3d4", 2),
		"rk_prod_" + strings.Repeat("A1b2C3d4", 2),
	}
	for _, source := range tests {
		redactor := New()
		out, changed, err := redactor.redactBytes([]byte(source))
		if err != nil || !changed || string(out) != "<VENDOR_TOKEN>" || redactor.Summary().ItemsRedacted != 1 {
			t.Fatalf("redaction of %q = %q, changed=%t, summary=%#v, err=%v", source, out, changed, redactor.Summary(), err)
		}
	}
}

func TestKnownSecretBoundaries(t *testing.T) {
	t.Parallel()
	token := "ghp_" + strings.Repeat("A1", 18)

	redactor := New()
	out, changed, err := redactor.redactBytes([]byte("(" + token + ")."))
	if err != nil || !changed || string(out) != "(<VENDOR_TOKEN>)." {
		t.Fatalf("punctuated token redaction = %q, changed=%t, err=%v", out, changed, err)
	}

	for _, source := range []string{"x" + token, token + "Z", token + "_suffix"} {
		out, changed, err = New().redactBytes([]byte(source))
		if err != nil || changed || string(out) != source {
			t.Fatalf("partial token redaction of %q = %q, changed=%t, err=%v", source, out, changed, err)
		}
	}
}

func TestLongCredentialIsFullyRedacted(t *testing.T) {
	t.Parallel()
	source := "CLIENT_SECRET=" + strings.Repeat("Ab1!Cd2@", 1_500)
	out, changed, err := New().redactBytes([]byte(source))
	if err != nil || !changed || string(out) != "CLIENT_SECRET=<CREDENTIAL>" {
		t.Fatalf("long credential redaction length=%d, changed=%t, err=%v", len(out), changed, err)
	}
}

func TestFalsePositiveCorpus(t *testing.T) {
	t.Parallel()
	texts := []string{
		"Go 1.26.5 supports this source file.",
		"Model gpt-5.6-sol has a 2,000,000 token context window.",
		"Request 019de4fc-490f-759e-8bcf-fa86a096d0fe completed at 2026-08-26T12:34:56Z.",
		"The checksum is 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.",
		"Documentation contact dev@example.com and admin@localhost.",
		"Documentation contact dev@subdomain.example.com is reserved too.",
		"Use card 4242 4242 4242 4242 in the test environment.",
		"Presidio test card 1220 0000 0000 003 remains safe documentation.",
		"The database counter 4532015112830366 is an opaque integer.",
		`discard_number="4532015112830366"`,
		`companion_value="4532015112830366"`,
		"The unformatted values 4155552671 and 856456789 are ordinary counters here.",
		"Private networks include 10.0.0.1 and 2001:db8::1.",
		"The password policy requires twelve characters.",
		"Set password to changeme in this example.",
		"A token budget of 20000 is valid.",
		"The sk-short-example value is not a credential.",
		"The sk-feature-branch-for-the-new-redaction-work value is not a credential.",
		"Masked examples hf_" + strings.Repeat("x", 34) + " and pplx-" + strings.Repeat("x", 48) + " stay visible.",
		"Masked GitHub token github_pat_" + strings.Repeat("x", 22) + "_" + strings.Repeat("x", 59) + " stays visible.",
		"Masked GitLab token glpat-XXXXXXXXXXX-XXXXXXXX stays visible.",
		"Masked GitLab routable token glpat-xxxxxxxx-xxxxxxxxxxxxxxxxxx.xxxxxxxxx stays visible.",
		"Masked GitLab job token glcbt-Ab1_" + strings.Repeat("x", 20) + " stays visible.",
		"Masked Notion token ntn_12345678901" + strings.Repeat("x", 35) + " stays visible.",
		"Malformed Notion value ntn_12345678901abc stays visible.",
		"Malformed Databricks value dapi123456789012345678a9bc01234defg5 stays visible.",
		"The public AWS documentation key is AKIAIOSFODNN7EXAMPLE.",
		"Firebase example key AIzaSyabcdefghijklmnopqrstuvwxyz1234567 remains visible.",
		"Firebase SDK key AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs remains visible.",
		"The Slack documentation webhook is https://hooks.slack.com/" + "services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX.",
		"Masked SendGrid value SG." + strings.Repeat("x", 22) + "." + strings.Repeat("x", 43) + " stays visible.",
		"Masked Telegram value 123456789:AA" + strings.Repeat("x", 33) + " stays visible.",
		"Masked 1Password key A3-XXXXXX-XXXXXXXXXXX-XXXXX-XXXXX-XXXXX stays visible.",
		"Masked Basic value Authorization: Basic dXNlcjp4eHh4eHh4eA== stays visible.",
		"const API_TOKEN = someIdentifierName",
		"TOKEN=550e8400-e29b-41d4-a716-446655440000",
		"revision=550e8400-e29b-41d4-a716-446655440000",
		"etag=550e8400-e29b-41d4-a716-446655440000",
		"sha256=" + strings.Repeat("a", 64),
		"md5=" + strings.Repeat("b", 32),
		"integrity=sha512-AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789",
		"color: #fff; background: #aabbcc;",
		"data:image/png;base64," + strings.Repeat("A", 40),
		"data:application/octet-stream;base64," + strings.Repeat("B", 40),
		"The signed date +2026-08-27 is not a phone number.",
		"The reserved example phone is 212-555-0123.",
		"The unrelated record 960121-1234567 has no identity context.",
		"An incomplete block -----BEGIN PRIVATE KEY----- does not consume later text.",
		"Names such as Jane Doe and addresses such as 123 Main Street need a contextual model.",
		"DNI 12345678A and CPF 529.982.247-24 have invalid check digits.",
		"Canadian SIN 046 454 286 is in a reserved range.",
	}
	for _, source := range texts {
		redactor := New()
		out, changed, err := redactor.redactBytes([]byte(source))
		if err != nil {
			t.Fatalf("%q: %v", source, err)
		}
		if changed || string(out) != source || redactor.Summary().ItemsRedacted != 0 {
			t.Fatalf("false positive: %q became %q", source, out)
		}
	}
}

func TestArbitrarySignatureFieldDoesNotDisableRedaction(t *testing.T) {
	t.Parallel()
	raw := map[string]json.RawMessage{
		"input": json.RawMessage(`[{"type":"input_text","text":"alice@corp.io","signature":"application-signature"}]`),
	}
	redactor := New()
	if err := redactor.RedactRequestFields(raw, SurfaceResponses); err != nil {
		t.Fatal(err)
	}
	if redactor.Summary().ItemsRedacted != 1 || !bytes.Contains(raw["input"], []byte("<EMAIL_ADDRESS>")) {
		t.Fatalf("arbitrary signature field disabled redaction: summary=%#v input=%s", redactor.Summary(), raw["input"])
	}
}

func TestJSONFieldScopeAndSignedObjects(t *testing.T) {
	t.Parallel()
	githubToken := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	raw := map[string]json.RawMessage{
		"model": json.RawMessage(`"alice@corp.io"`),
		"messages": json.RawMessage(fmt.Sprintf(`[
			{"role":"user","content":"Email alice@corp.io","id":%q,"name":%q,
			 "details":"Escaped alice\u0040corp.io"},
			{"role":"assistant","reasoning":"signed@corp.io","reasoning_details":[
				{"index":0,"type":"reasoning.text","text":"signed@corp.io","signature":"signed-payload"}
			]}
		]`, githubToken, githubToken)),
		"metadata": json.RawMessage(`{"email":"metadata@corp.io"}`),
		"tools":    json.RawMessage(fmt.Sprintf(`[{"type":"function","function":{"name":%q,"description":"Contact tools@corp.io"}}]`, githubToken)),
	}

	redactor := New()
	if err := redactor.RedactRequestFields(raw, SurfaceChat); err != nil {
		t.Fatal(err)
	}
	if redactor.Summary().ItemsRedacted != 3 {
		t.Fatalf("items_redacted = %d, want 3", redactor.Summary().ItemsRedacted)
	}
	messages := string(raw["messages"])
	if strings.Count(messages, "EMAIL_ADDRESS") != 2 || strings.Count(messages, "signed@corp.io") != 2 {
		t.Fatalf("unexpected messages redaction: %s", messages)
	}
	if strings.Count(messages, githubToken) != 2 {
		t.Fatalf("protocol id or name changed: %s", messages)
	}
	if !strings.Contains(string(raw["tools"]), "EMAIL_ADDRESS") {
		t.Fatalf("tool description was not redacted: %s", raw["tools"])
	}
	if string(raw["model"]) != `"alice@corp.io"` || !bytes.Contains(raw["metadata"], []byte("metadata@corp.io")) {
		t.Fatal("a field outside the text surface changed")
	}
	for name, value := range raw {
		if !json.Valid(value) {
			t.Fatalf("field %s is invalid JSON: %s", name, value)
		}
	}
}

func TestEncryptedObjectRollsBackNestedRedactions(t *testing.T) {
	t.Parallel()
	raw := map[string]json.RawMessage{
		"input": json.RawMessage(`[
			{"type":"message","role":"user","content":[{"type":"input_text","text":"outside@corp.io"}]},
			{"type":"reasoning","summary":[{"type":"summary_text","text":"inside@corp.io"}],"encrypted_content":"ciphertext"}
		]`),
	}
	redactor := New()
	if err := redactor.RedactRequestFields(raw, SurfaceResponses); err != nil {
		t.Fatal(err)
	}
	if redactor.Summary().ItemsRedacted != 1 || !bytes.Contains(raw["input"], []byte("<EMAIL_ADDRESS>")) || !bytes.Contains(raw["input"], []byte("inside@corp.io")) {
		t.Fatalf("unexpected encrypted-object handling: summary=%#v input=%s", redactor.Summary(), raw["input"])
	}
}

func TestValidEscapedJSONString(t *testing.T) {
	t.Parallel()
	source := []byte(`{"text":"path:\/users\/alice and alice\u0040corp.io"}`)
	out, changed, err := New().redactJSON(source)
	if err != nil || !changed || !json.Valid(out) || !bytes.Contains(out, []byte("EMAIL_ADDRESS")) {
		t.Fatalf("redaction = %q, changed=%t, err=%v", out, changed, err)
	}
}

func TestIncompleteEncryptedShapeDoesNotBypassRedaction(t *testing.T) {
	t.Parallel()
	source := []byte(`{"type":"reasoning.encrypted","text":"alice@corp.io"}`)
	out, changed, err := New().redactJSON(source)
	if err != nil || !changed || !bytes.Contains(out, []byte("<EMAIL_ADDRESS>")) {
		t.Fatalf("redaction = %q, changed=%t, err=%v", out, changed, err)
	}
}

func TestRedactionIsTypedIrreversibleAndIdempotent(t *testing.T) {
	t.Parallel()
	source := []byte("alice@corp.io and alice@corp.io use 4532 0151 1283 0366")
	redactor := New()
	first, changed, err := redactor.redactBytes(source)
	if err != nil || !changed {
		t.Fatalf("first redaction changed=%t err=%v", changed, err)
	}
	if redactor.Summary().ItemsRedacted != 3 || bytes.Contains(first, []byte("alice")) || bytes.Contains(first, []byte("4532")) {
		t.Fatalf("unexpected first redaction: summary=%#v output=%s", redactor.Summary(), first)
	}
	secondRedactor := New()
	second, changed, err := secondRedactor.redactBytes(first)
	if err != nil || changed || !bytes.Equal(first, second) || secondRedactor.Summary().ItemsRedacted != 0 {
		t.Fatalf("redaction is not idempotent: changed=%t err=%v first=%s second=%s", changed, err, first, second)
	}
}

func TestOverlappingMatchesDoNotExposeEitherTail(t *testing.T) {
	t.Parallel()
	matches := normalizeMatches([]match{
		{start: 0, end: 10, entity: EntityEmail, priority: 80},
		{start: 5, end: 20, entity: EntityCredential, priority: 90},
		{start: 20, end: 25, entity: EntityPhone, priority: 72},
	})
	if len(matches) != 2 || matches[0].start != 0 || matches[0].end != 20 || matches[0].entity != EntityCredential ||
		matches[1].start != 20 || matches[1].end != 25 {
		t.Fatalf("unexpected normalized matches: %#v", matches)
	}
}

func TestEqualMatchesUseAStableEntityOrder(t *testing.T) {
	t.Parallel()
	matches := normalizeMatches([]match{
		{start: 0, end: 10, entity: EntityAustraliaACN, priority: 77},
		{start: 0, end: 10, entity: EntityAustraliaTFN, priority: 77},
	})
	if len(matches) != 1 || matches[0].entity != EntityAustraliaTFN {
		t.Fatalf("unexpected normalized match: %#v", matches)
	}
}

func TestCleanTextReturnsOriginalStorage(t *testing.T) {
	t.Parallel()
	source := []byte(strings.Repeat("ordinary source code and prose 12345\n", 4096))
	out, changed, err := New().redactBytes(source)
	if err != nil || changed {
		t.Fatalf("clean redaction changed=%t err=%v", changed, err)
	}
	if len(out) != len(source) || &out[0] != &source[0] {
		t.Fatal("clean input was copied")
	}
}

func TestMatchLimitFailsClosed(t *testing.T) {
	t.Parallel()
	source := []byte(strings.Repeat("person@corp.io ", maxMatchesPerText+1))
	_, _, err := New().redactBytes(source)
	if !errors.Is(err, ErrMatchLimit) {
		t.Fatalf("error = %v, want ErrMatchLimit", err)
	}
}

func TestNestingLimitFailsClosed(t *testing.T) {
	t.Parallel()
	source := []byte(strings.Repeat("[", 130) + `"alice@corp.io"` + strings.Repeat("]", 130))
	_, _, err := New().redactJSON(source)
	if !errors.Is(err, ErrNestingLimit) {
		t.Fatalf("error = %v, want ErrNestingLimit", err)
	}
}

func FuzzRedactBytes(f *testing.F) {
	for _, seed := range []string{
		"plain text",
		"alice@corp.io",
		"SSN 856-45-6789",
		"2026-08-27 415-555-2671 212-555-2672",
		"Call +44 (20) 7123 4567",
		"Aadhaar 9999:9999:0019",
		"Personnummer 871220-2384",
		`card_number="4532015112830366"`,
		"CLIENT_SECRET=AbCdEf0123456789!",
		"Masked hf_" + strings.Repeat("x", 34),
		"\x00\xff malformed UTF-8",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, source []byte) {
		redactor := New()
		out, changed, err := redactor.redactBytes(source)
		if err != nil {
			if !errors.Is(err, ErrMatchLimit) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		if changed != !bytes.Equal(source, out) || changed != (redactor.Summary().ItemsRedacted > 0) {
			t.Fatalf("inconsistent result: changed=%t summary=%#v", changed, redactor.Summary())
		}
		second, changed, secondErr := New().redactBytes(out)
		if secondErr != nil || changed || !bytes.Equal(out, second) {
			t.Fatalf("output was not stable: err=%v changed=%t", secondErr, changed)
		}
	})
}

func FuzzRedactJSON(f *testing.F) {
	for _, seed := range []string{
		`{"text":"alice@corp.io"}`,
		`[{"type":"input_text","text":"plain text"}]`,
		`{"type":"reasoning.text","text":"signed@corp.io","signature":"opaque"}`,
		`[{"role":"assistant","reasoning":"signed@corp.io","reasoning_details":[{"index":0,"type":"reasoning.text","text":"signed@corp.io","signature":"opaque"}]}]`,
		`[{"type":"reasoning","summary":[{"type":"summary_text","text":"signed@corp.io"}],"encrypted_content":"opaque"}]`,
		`"escaped alice\u0040corp.io"`,
		`{"text":"Call +44 (20) 7123 4567"}`,
		`{"text":"Masked hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, source []byte) {
		valid := json.Valid(source)
		for _, context := range []jsonValueContext{jsonContextGeneral, jsonContextChatMessages, jsonContextResponsesInput} {
			redactor := New()
			out, _, err := redactor.redactJSONContext(source, context)
			if errors.Is(err, ErrNestingLimit) || errors.Is(err, ErrMatchLimit) {
				continue
			}
			if err != nil {
				if valid {
					t.Fatalf("valid JSON failed in context %d: %v", context, err)
				}
				if redactor.Summary().ItemsRedacted != 0 {
					t.Fatalf("invalid JSON changed metrics in context %d: %#v", context, redactor.Summary())
				}
				continue
			}
			if !valid {
				t.Fatalf("invalid JSON was accepted in context %d: %q", context, source)
			}
			if !json.Valid(out) {
				t.Fatalf("redacted output is invalid JSON in context %d: %q", context, out)
			}
			second, changed, secondErr := New().redactJSONContext(out, context)
			if secondErr != nil || changed || !bytes.Equal(out, second) {
				t.Fatalf("JSON output was not stable in context %d: err=%v changed=%t", context, secondErr, changed)
			}
		}
	})
}

func BenchmarkRedactCleanTwoMillionTokens(b *testing.B) {
	text := bytes.Repeat([]byte("ordinary source code and prose "), 400_000)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, changed, err := New().redactBytes(text); err != nil || changed {
			b.Fatalf("changed=%t err=%v", changed, err)
		}
	}
}

func BenchmarkRedactCleanTwoMillionTokensAllSupportedPatterns(b *testing.B) {
	text := bytes.Repeat([]byte("ordinary source code and prose "), 400_000)
	policy, err := CompilePolicy(Options{Patterns: supportedPatterns[:]})
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, changed, err := NewWithPolicy(policy).redactBytes(text); err != nil || changed {
			b.Fatalf("changed=%t err=%v", changed, err)
		}
	}
}

func BenchmarkRedactCleanTwoMillionTokensWithCustomPattern(b *testing.B) {
	text := bytes.Repeat([]byte("ordinary source code and prose "), 400_000)
	policy, err := CompilePolicy(Options{CustomPatterns: []CustomPattern{{Expression: `EMP-[0-9]{6}\b`}}})
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, changed, err := NewWithPolicy(policy).redactBytes(text); err != nil || changed {
			b.Fatalf("changed=%t err=%v", changed, err)
		}
	}
}

func BenchmarkRedactDensePII(b *testing.B) {
	text := bytes.Repeat([]byte("alice@corp.io (415) 555-2671 "), 8_000)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, changed, err := New().redactBytes(text); err != nil || !changed {
			b.Fatalf("changed=%t err=%v", changed, err)
		}
	}
}
