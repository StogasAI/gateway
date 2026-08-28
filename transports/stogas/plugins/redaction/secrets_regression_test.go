package redaction

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestTelegramTokenCurrentShapeAndBounds(t *testing.T) {
	t.Parallel()
	body := "Ab1C2d3E4f5G6h7I8j9K0l1M2n3O4p5Q6r7"
	for _, botID := range []string{"12345", "1234567890123456"} {
		source := botID + ":" + body
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || !changed || string(out) != "<VENDOR_TOKEN>" {
			t.Fatalf("redaction of %q = %q, changed=%t, err=%v", source, out, changed, err)
		}
	}
	for _, botID := range []string{"1234", "12345678901234567"} {
		source := botID + ":" + body
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || changed || string(out) != source {
			t.Fatalf("out-of-range bot ID %q was redacted as %q", source, out)
		}
	}
}

func TestJWTRequiresThreeCanonicalParts(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		"eyJhbGciOiJIUzI1NiJ9.cGxhaW4.SflKxwRJSMeK",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghi",
		"eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxIn0.SflKxwRJSMeK",
	} {
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || changed || string(out) != source {
			t.Fatalf("malformed JWT %q was redacted as %q (err=%v)", source, out, err)
		}
	}
}

func TestBasicCredentialValidation(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"user:Sup3rSecret!", "müller:Sëcret123!"} {
		padded := base64.StdEncoding.EncodeToString([]byte(raw))
		rawEncoding := base64.RawStdEncoding.EncodeToString([]byte(raw))
		for _, encoded := range []string{padded, rawEncoding} {
			source := "Authorization: Basic " + encoded
			out, changed, err := New().redactBytes([]byte(source))
			if err != nil || !changed || string(out) != "Authorization: Basic <CREDENTIAL>" {
				t.Fatalf("redaction of %q = %q, changed=%t, err=%v", source, out, changed, err)
			}
		}
	}

	invalidDecoded := [][]byte{
		[]byte("missing-colon"),
		[]byte(":password"),
		[]byte("user:"),
		[]byte("user:xxxxxxxx"),
		append([]byte("user:"), 0, 's', 'e', 'c', 'r', 'e', 't'),
	}
	for _, decoded := range invalidDecoded {
		encoded := base64.StdEncoding.EncodeToString(decoded)
		source := "Authorization: Basic " + encoded
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || changed || !bytes.Equal(out, []byte(source)) {
			t.Fatalf("invalid Basic credential %q was redacted as %q (err=%v)", decoded, out, err)
		}
	}
	nonCanonical := "Authorization: Basic dXNlcjpzZWNyZXR="
	out, changed, err := New().redactBytes([]byte(nonCanonical))
	if err != nil || changed || string(out) != nonCanonical {
		t.Fatalf("non-canonical Basic value was redacted as %q (err=%v)", out, err)
	}
}

func TestDatabaseCredentialURLRequiresARealPassword(t *testing.T) {
	t.Parallel()
	positives := []string{
		"redis://:Sup3rSecret!@cache.internal:6379/0",
		"rediss://:Sup3rSecret!@cache.internal:6379/0",
		"postgresql://app:hunter2@db.internal/data",
		"mongodb+srv://app:Sup3rSecret!@cluster.internal/data?retryWrites=true",
	}
	for _, source := range positives {
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || !changed || string(out) != "<DATABASE_URL>" {
			t.Fatalf("redaction of %q = %q, changed=%t, err=%v", source, out, changed, err)
		}
	}
	for _, source := range []string{
		"postgresql://:Sup3rSecret!@db.internal/data",
		"postgresql://app@db.internal/data",
		"postgresql://app:@db.internal/data",
		"postgresql://db.internal/data",
		"postgresql://app:password@db.internal/data",
		"postgresql://app:changeme@db.internal/data",
		"postgresql://app:xxxxxxxx@db.internal/data",
		"postgresql://app:${DB_PASSWORD}@db.internal/data",
	} {
		matches, err := scanDatabaseCredentials([]byte(source), nil, defaultEntityMask)
		if err != nil || len(matches) != 0 {
			t.Fatalf("URL without valid userinfo %q produced matches=%#v err=%v", source, matches, err)
		}
	}
}

func TestCredentialAssignmentForms(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		"export SERVICE_SECRET=AbCdEf0123456789GhIjKlMn",
		`{"client_secret":"AbCdEf0123456789GhIjKlMn"}`,
		"-e API_KEY=AbCdEf0123456789GhIjKlMn",
		"PASSWORD=huntertwo",
		`password: "correct horse battery staple"`,
	} {
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || !changed || !bytes.Contains(out, []byte("<CREDENTIAL>")) {
			t.Fatalf("credential redaction of %q = %q, changed=%t, err=%v", source, out, changed, err)
		}
	}
}

func TestStrongVendorTokensRejectMaskedAndPartialShapes(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		"dp.pt." + strings.Repeat("x", 43),
		"ops_eyJ" + strings.Repeat("x", 250),
		"pscale_tkn_" + strings.Repeat("x", 32),
		"pscale_oauth_" + strings.Repeat("x", 32),
		"pscale_pw_" + strings.Repeat("x", 32),
		"pul-" + strings.Repeat("a", 40),
		"sntryu_" + strings.Repeat("a", 64),
		"dp.pt." + strings.Repeat("a1B2c3D4", 5),
		"pul-" + strings.Repeat("0123456789abcdef", 2),
	} {
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || changed || string(out) != source {
			t.Fatalf("masked or partial token %q was redacted as %q (err=%v)", source, out, err)
		}
	}
}

func TestCurrentGitHubAndSlackShapes(t *testing.T) {
	t.Parallel()
	githubBody := strings.Repeat("A1b2C3d4", 2) + "E5f6G7_" + strings.Repeat("H8i9J0k1", 7) + "L2m"
	workflowBody := strings.Repeat("A1b2C3d4", 5) + "Z9+/x"
	for _, source := range []string{
		"github_pat_" + githubBody,
		"xapp-1-ABCDEF123456-1234567890-abcdef1234567890",
		"https://hooks.slack.com/workflows/" + workflowBody,
		"hooks.slack.com/triggers/" + workflowBody,
	} {
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || !changed || string(out) != "<VENDOR_TOKEN>" {
			t.Fatalf("redaction of %q = %q, changed=%t, err=%v", source, out, changed, err)
		}
	}
}

func TestGitHubFineGrainedTokenRequiresCanonicalSeparator(t *testing.T) {
	t.Parallel()
	body := strings.Repeat("A1b2C3d4", 10) + "Z9"
	source := "github_pat_" + body
	out, changed, err := New().redactBytes([]byte(source))
	if err != nil || changed || string(out) != source {
		t.Fatalf("non-canonical token %q was redacted as %q (err=%v)", source, out, err)
	}
}

func TestSlackExamplesAndPartialURLsRemainVisible(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		"https://hooks.slack.com/" + "services/T0A1B2C3D/B4D5E6F7G/XXXXXXXXXXXXXXXXXXXXXXXX",
		"https://hooks.slack.com/workflows/" + strings.Repeat("x", 43),
		"https://hooks.slack.com/triggers/short",
		"xapp-1-EXAMPLE-123-example",
	} {
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || changed || string(out) != source {
			t.Fatalf("Slack example %q was redacted as %q (err=%v)", source, out, err)
		}
	}
}

func TestCredentialsInGeneralURLs(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		"https://alice:Sup3rSecret!@api.internal/v1",
		"sftp://deploy:AbCdEf012345!@files.internal/releases",
	} {
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || !changed || string(out) != "<CREDENTIAL>" {
			t.Fatalf("redaction of %q = %q, changed=%t, err=%v", source, out, changed, err)
		}
	}
}

func TestJWTSentencePunctuationAndSuffixBoundaries(t *testing.T) {
	t.Parallel()
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	for _, test := range []struct {
		source string
		want   string
	}{
		{source: token + ".", want: "<JSON_WEB_TOKEN>."},
		{source: "(" + token + ").", want: "(<JSON_WEB_TOKEN>)."},
		{source: token + ". next", want: "<JSON_WEB_TOKEN>. next"},
	} {
		out, changed, err := New().redactBytes([]byte(test.source))
		if err != nil || !changed || string(out) != test.want {
			t.Fatalf("JWT redaction of %q = %q, changed=%t, err=%v", test.source, out, changed, err)
		}
	}

	for _, source := range []string{token + ".extra", "prefix" + token} {
		out, changed, err := New().redactBytes([]byte(source))
		if err != nil || changed || string(out) != source {
			t.Fatalf("partial JWT %q was redacted as %q (err=%v)", source, out, err)
		}
	}
}
