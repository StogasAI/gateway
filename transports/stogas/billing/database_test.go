package billing

import "testing"

func TestGatewayFunctionQueryQualifiesPgrollSchema(t *testing.T) {
	db := &GatewayDB{schemaName: "public_0001_initial_schema"}
	query := db.functionQuery("authorize_gateway_hold", "$1::text")
	want := "select * from \"public_0001_initial_schema\".\"authorize_gateway_hold\"(\n$1::text\n);"
	if query != want {
		t.Fatalf("query = %q, want %q", query, want)
	}
}

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
