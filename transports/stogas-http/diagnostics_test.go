package stogashttp

import "testing"

func TestMemoryPressureDistinguishesZeroFromUnavailable(t *testing.T) {
	for _, test := range []struct {
		name, raw  string
		some, full *uint64
	}{
		{name: "unsupported"},
		{name: "malformed", raw: "some total=-1\nfull total=18446744073709551616"},
		{name: "missing totals", raw: "some avg10=0.00\nfull avg10=1.00"},
		{name: "kernel sample", raw: "some avg10=0.00 avg60=0.12 avg300=0.34 total=123456\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n", some: new(uint64(123456)), full: new(uint64(0))},
	} {
		t.Run(test.name, func(t *testing.T) {
			some, full := parseMemoryPressure(test.raw)
			for i, pair := range [][2]*uint64{{some, test.some}, {full, test.full}} {
				if (pair[0] == nil) != (pair[1] == nil) || (pair[0] != nil && *pair[0] != *pair[1]) {
					t.Fatalf("measurement %d: got %v, want %v", i, pair[0], pair[1])
				}
			}
		})
	}
}
