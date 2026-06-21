package billing

import "testing"

func TestPgrollSearchPathAddsPublicFallback(t *testing.T) {
	searchPath, err := pgrollSearchPath("public_001_initial")
	if err != nil {
		t.Fatalf("pgrollSearchPath returned error: %v", err)
	}
	if searchPath != "public_001_initial,public" {
		t.Fatalf("searchPath = %s, want public_001_initial,public", searchPath)
	}
}

func TestPgrollSearchPathDoesNotDuplicatePublic(t *testing.T) {
	searchPath, err := pgrollSearchPath("public")
	if err != nil {
		t.Fatalf("pgrollSearchPath returned error: %v", err)
	}
	if searchPath != "public" {
		t.Fatalf("searchPath = %s, want public", searchPath)
	}
}

func TestPgrollSearchPathRejectsMalformedSchema(t *testing.T) {
	if _, err := pgrollSearchPath("public;drop schema public"); err == nil {
		t.Fatal("pgrollSearchPath returned nil error for malformed schema")
	}
}
