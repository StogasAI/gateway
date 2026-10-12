package billing

import "testing"

func TestValidateDatabaseSchemaRejectsMalformedSchema(t *testing.T) {
	if err := ValidateDatabaseSchema("public;drop schema public"); err == nil {
		t.Fatal("ValidateDatabaseSchema returned nil error for malformed schema")
	}
}

func TestValidateDatabaseSchemaRequiresSchema(t *testing.T) {
	if err := ValidateDatabaseSchema("  "); err == nil {
		t.Fatal("ValidateDatabaseSchema returned nil error for an empty schema")
	}
}
