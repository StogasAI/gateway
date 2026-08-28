package redaction

import (
	"testing"
	"time"
)

func TestEveryEntityHasAStableTypedPlaceholder(t *testing.T) {
	t.Parallel()
	expected := map[Entity]string{
		EntityEmail:                  "<EMAIL_ADDRESS>",
		EntityPhone:                  "<PHONE_NUMBER>",
		EntityIPAddress:              "<IP_ADDRESS>",
		EntityPaymentCard:            "<PAYMENT_CARD>",
		EntityIBAN:                   "<IBAN>",
		EntityUSSSN:                  "<US_SSN>",
		EntityUSITIN:                 "<US_ITIN>",
		EntityUSRoutingNumber:        "<US_ROUTING_NUMBER>",
		EntityUKNHS:                  "<UK_NHS_NUMBER>",
		EntityUKNINO:                 "<UK_NATIONAL_INSURANCE_NUMBER>",
		EntityCanadaSIN:              "<CA_SOCIAL_INSURANCE_NUMBER>",
		EntityAustraliaTFN:           "<AU_TAX_FILE_NUMBER>",
		EntityAustraliaABN:           "<AU_BUSINESS_NUMBER>",
		EntityAustraliaACN:           "<AU_COMPANY_NUMBER>",
		EntityAustraliaMedicare:      "<AU_MEDICARE_NUMBER>",
		EntityIndiaAadhaar:           "<IN_AADHAAR_NUMBER>",
		EntityBrazilCPF:              "<BR_CPF>",
		EntityBrazilCNPJ:             "<BR_CNPJ>",
		EntitySpainDNI:               "<ES_NATIONAL_ID>",
		EntityItalyFiscalCode:        "<IT_FISCAL_CODE>",
		EntityPolandPESEL:            "<PL_PESEL>",
		EntityKoreaRRN:               "<KR_RESIDENT_NUMBER>",
		EntityFinlandPersonalID:      "<FI_PERSONAL_ID>",
		EntityThailandNationalID:     "<TH_NATIONAL_ID>",
		EntitySingaporeNationalID:    "<SG_NATIONAL_ID>",
		EntityChinaResidentID:        "<CN_RESIDENT_ID>",
		EntityIsraelNationalID:       "<IL_NATIONAL_ID>",
		EntitySouthAfricaID:          "<ZA_NATIONAL_ID>",
		EntityTurkeyNationalID:       "<TR_NATIONAL_ID>",
		EntityGermanyTaxID:           "<DE_TAX_ID>",
		EntitySwedenPersonalID:       "<SE_PERSONAL_ID>",
		EntityUSNPI:                  "<US_NPI>",
		EntityKoreaBusinessNumber:    "<KR_BUSINESS_REGISTRATION_NUMBER>",
		EntityItalyVAT:               "<IT_VAT_NUMBER>",
		EntityNigeriaNIN:             "<NG_NATIONAL_ID>",
		EntityUSMedicareID:           "<US_MEDICARE_ID>",
		EntityGermanyHealthInsurance: "<DE_HEALTH_INSURANCE_ID>",
		EntityGermanySocialSecurity:  "<DE_SOCIAL_SECURITY_NUMBER>",
		EntityPrivateKey:             "<PRIVATE_KEY>",
		EntityVendorToken:            "<VENDOR_TOKEN>",
		EntityJSONWebToken:           "<JSON_WEB_TOKEN>",
		EntityCredential:             "<CREDENTIAL>",
		EntityDatabaseCredential:     "<DATABASE_URL>",
	}
	if len(expected) != int(EntityDatabaseCredential) {
		t.Fatalf("entity inventory has %d entries, enum has %d", len(expected), EntityDatabaseCredential)
	}
	seen := make(map[string]Entity, len(expected))
	for entity := EntityEmail; entity <= EntityDatabaseCredential; entity++ {
		want, ok := expected[entity]
		if !ok {
			t.Fatalf("entity %d is absent from the inventory", entity)
		}
		if got := placeholder(entity); got != want {
			t.Errorf("entity %d placeholder = %q, want %q", entity, got, want)
		}
		if previous, duplicate := seen[want]; duplicate {
			t.Errorf("entities %d and %d share placeholder %q", previous, entity, want)
		}
		seen[want] = entity
		out, changed, err := New().redactBytes([]byte(want))
		if err != nil || changed || string(out) != want {
			t.Errorf("placeholder %q was not idempotent: output=%q changed=%t err=%v", want, out, changed, err)
		}
	}
	if custom := placeholder(entityCustom); custom != "<CUSTOM_PII>" {
		t.Fatalf("custom placeholder = %q", custom)
	} else if _, duplicate := seen[custom]; duplicate {
		t.Fatalf("custom placeholder %q duplicates a built-in placeholder", custom)
	}
}

func TestScannerMasksCoverEveryBuiltInEntityOnce(t *testing.T) {
	t.Parallel()
	groups := []entityMask{
		maskOf(EntityEmail),
		maskOf(EntityIPAddress),
		secretEntityMask,
		structuredNumberEntityMask,
		structuredIdentifierEntityMask,
	}
	var covered entityMask
	for index, group := range groups {
		if overlap := covered & group; overlap != 0 {
			t.Fatalf("scanner group %d overlaps earlier groups: %#x", index, overlap)
		}
		covered |= group
	}
	if covered != allBuiltInEntityMask {
		t.Fatalf("scanner coverage = %#x, want %#x", covered, allBuiltInEntityMask)
	}
	if EntityDatabaseCredential > 64 {
		t.Fatalf("entity mask cannot represent entity %d", EntityDatabaseCredential)
	}
}

func TestSummaryReportsBoundedPluginDuration(t *testing.T) {
	t.Parallel()
	redactor := &Redactor{items: 2, duration: 1_234*time.Microsecond + 999*time.Nanosecond}
	if summary := redactor.Summary(); summary.ItemsRedacted != 2 || summary.DurationUS != 1_234 {
		t.Fatalf("summary = %#v", summary)
	}
	redactor.duration = (time.Duration(^uint32(0)) + 1) * time.Microsecond
	if summary := redactor.Summary(); summary.DurationUS != ^uint32(0) {
		t.Fatalf("saturated summary = %#v", summary)
	}
}

func TestKnownSecretSpecInventory(t *testing.T) {
	t.Parallel()
	seen := make(map[string]struct{})
	count := 0
	for initial, specs := range secretSpecsByInitial {
		for _, spec := range specs {
			count++
			if spec.prefix == "" || int(spec.prefix[0]) != initial {
				t.Fatalf("secret prefix %q is in bucket %d", spec.prefix, initial)
			}
			if spec.minimumBody < 0 || spec.maximumBody < spec.minimumBody || spec.characters < secretAlphanumeric || spec.characters > secretExtendedToken {
				t.Fatalf("invalid secret specification: %#v", spec)
			}
			if _, duplicate := seen[spec.prefix]; duplicate {
				t.Fatalf("duplicate secret prefix %q", spec.prefix)
			}
			seen[spec.prefix] = struct{}{}
		}
	}
	if count < 60 {
		t.Fatalf("secret inventory has only %d entries", count)
	}
}
