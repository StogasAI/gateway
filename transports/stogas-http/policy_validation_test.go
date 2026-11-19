package stogashttp

import (
	"errors"
	"fmt"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/plugins/exporter/exportconfig"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// overExported is a policy and a rule of it that export to ten destinations together.
func overExported() []*policy.Plugins {
	sections := make([]*policy.Plugins, 2)
	for i := range sections {
		export := &exportconfig.Config{}
		for j := range 5 {
			export.Destinations = append(export.Destinations, exportconfig.Destination{URL: fmt.Sprintf("https://logs-%d-%d.example.com/ingest", i, j)})
		}
		sections[i] = &policy.Plugins{Export: export}
	}
	return sections
}

// A check that sends no keys opens nothing, so its error may say what is wrong with what it sent.
// One that sends keys may have opened private settings, so its error stays generic.
func TestInvalidPolicyMessageNamesOnlyWhatTheCallerSent(t *testing.T) {
	detailed := fmt.Errorf("%w: unknown redaction preset email_adress", policy.ErrInvalidConfig)
	for _, test := range []struct {
		name   string
		err    error
		opened bool
		want   string
	}{
		{"an error in readable settings", detailed, false, "Policy configuration is invalid: unknown redaction preset email_adress"},
		{"an error after opening settings", detailed, true, "Policy configuration is invalid"},
		{"an error without detail", policy.ErrInvalidConfig, false, "Policy configuration is invalid"},
		{"an error from elsewhere", errors.New("unknown redaction preset email_adress"), false, "Policy configuration is invalid"},
		{"a bound of one policy after opening settings", policy.CheckSections(overExported()), true, "Policy configuration is invalid: a policy exports to at most 8 destinations, counting its rules"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := invalidPolicyMessage(test.err, test.opened); got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}
