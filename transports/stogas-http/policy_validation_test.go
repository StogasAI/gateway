package stogashttp

import (
	"errors"
	"fmt"
	"testing"

	"github.com/maximhq/bifrost/transports/stogas/policy"
)

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
		{"a nested error", policy.ErrSourceBudget, false, "Policy configuration is invalid: combined policy exceeds its compilation budget"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := invalidPolicyMessage(test.err, test.opened); got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}
