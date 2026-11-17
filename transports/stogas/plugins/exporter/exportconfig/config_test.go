package exportconfig

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"testing"
)

func sampleOf(t *testing.T, raw string) *Sample {
	t.Helper()
	var d Destination
	if err := json.Unmarshal([]byte(`{"url":"https://receiver.example/","sample":`+raw+`}`), &d); err != nil {
		t.Fatalf("sample %s: %v", raw, err)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("sample %s: %v", raw, err)
	}
	return d.Sample
}

func TestSampleReadsOneRateOrARatePerOutcome(t *testing.T) {
	for raw, want := range map[string]Sample{
		`1`:                                      {1, 1, 1, 1, 1},
		`0.25`:                                   {0.25, 0.25, 0.25, 0.25, 0.25},
		`{"failed":1,"rejected":1}`:              {0, 1, 0, 1, 0},
		`{"success":0.1,"failed":1}`:             {0.1, 1, 0, 0, 0},
		`{"cancelled":0.5,"unknown":0.75}`:       {0, 0, 0.5, 0, 0.75},
		`{"success":1e-9}`:                       {1e-9, 0, 0, 0, 0},
		` {"success" : 1 , "failed" : 0.5 } `:    {1, 0.5, 0, 0, 0},
		`1.0`:                                    {1, 1, 1, 1, 1},
		`{"success":1,"failed":1,"cancelled":1}`: {1, 1, 1, 0, 0},
	} {
		got := sampleOf(t, raw)
		if got == nil || *got != want {
			t.Fatalf("sample %s = %v, want %v", raw, got, want)
		}
	}
	for _, raw := range []string{
		`0`, `-0.5`, `1.0000001`, `2`, `"0.5"`, `true`, `[0.5]`, `{}`, `1e999`,
		`{"failure":1}`, `{"Success":1}`, `{"success":0}`, `{"success":0,"failed":1}`, `{"success":1.5}`,
		`{"success":-1}`, `{"success":"1"}`, `{"success":null}`, `{"success":[1]}`, `{"success":{}}`,
	} {
		var d Destination
		err := json.Unmarshal([]byte(`{"url":"https://receiver.example/","sample":`+raw+`}`), &d)
		if err == nil {
			err = d.Validate()
		}
		if err == nil {
			t.Fatalf("sample %s was accepted as %v", raw, d.Sample)
		}
	}
	// The policy reader refuses null fields before this type sees them, and the type refuses
	// one that reaches it.
	var sample Sample
	if json.Unmarshal([]byte(`null`), &sample) == nil {
		t.Fatal("a null sample was accepted")
	}
	// A destination built in code is held to the same rates.
	for _, sample := range []Sample{{}, {math.NaN(), 1, 1, 1, 1}, {1, 1, 1, 1, 1.5}, {-0.1, 1, 1, 1, 1}, {math.Inf(1), 0, 0, 0, 0}} {
		d := Destination{URL: "https://receiver.example/", Sample: &sample}
		if d.Validate() == nil {
			t.Fatalf("sample %v was accepted", sample)
		}
	}
}

func TestSampleWritesWhatItReads(t *testing.T) {
	for raw, want := range map[string]string{
		`0.25`:                       `0.25`,
		`{"failed":1,"rejected":1}`:  `{"failed":1,"rejected":1}`,
		`{"success":0.1,"failed":1}`: `{"failed":1,"success":0.1}`,
		// Every outcome at one rate is that rate.
		`{"success":0.5,"failed":0.5,"cancelled":0.5,"rejected":0.5,"unknown":0.5}`: `0.5`,
	} {
		encoded, err := json.Marshal(Destination{URL: "https://receiver.example/", Sample: sampleOf(t, raw)})
		if err != nil {
			t.Fatal(err)
		}
		if got := string(encoded); got != `{"url":"https://receiver.example/","sample":`+want+`}` {
			t.Fatalf("sample %s was written as %s", raw, got)
		}
		again := sampleOf(t, want)
		if *again != *sampleOf(t, raw) {
			t.Fatalf("sample %s read back as %v", raw, again)
		}
	}
	encoded, _ := json.Marshal(Destination{URL: "https://receiver.example/"})
	if string(encoded) != `{"url":"https://receiver.example/"}` {
		t.Fatalf("a destination without a sample was written as %s", encoded)
	}
}

func TestRateAndReach(t *testing.T) {
	every := Destination{}
	failures := Destination{Sample: sampleOf(t, `{"failed":1,"rejected":0.5}`)}
	for _, outcome := range Outcomes {
		if every.Rate(outcome) != 1 {
			t.Fatalf("a destination without a sample gets %v of %s", every.Rate(outcome), outcome)
		}
	}
	if every.Reach() != 1 || failures.Reach() != 1 || (Destination{Sample: sampleOf(t, `{"success":0.2,"failed":0.4}`)}).Reach() != 0.4 {
		t.Fatal("reach is the highest rate")
	}
	if failures.Rate("failed") != 1 || failures.Rate("rejected") != 0.5 || failures.Rate("success") != 0 || failures.Rate("cancelled") != 0 || failures.Rate("unknown") != 0 {
		t.Fatalf("rates = %v", failures.Sample)
	}
	// A name that is no outcome gets nothing from a destination that names outcomes.
	if failures.Rate("") != 0 || failures.Rate("FAILED") != 0 {
		t.Fatal("an unnamed outcome got records")
	}
}

// The positions are the first 32 bits of each ID's SHA-256, worked out apart
// from this code, so that a receiver can repeat the choice.
func TestPositionFollowsTheRequestID(t *testing.T) {
	for id, want := range map[string]float64{
		"01a14a2c-7ee1-7ad7-bbf6-4d3c4c79bfad": 2258492286.0 / (1 << 32),
		"01a14a2e-473b-7d85-a76b-9f3e43449388": 2596870353.0 / (1 << 32),
		"id":                                   2774615335.0 / (1 << 32),
		"":                                     3820012610.0 / (1 << 32),
	} {
		if got := Position(id); got != want {
			t.Fatalf("Position(%q) = %v, want %v", id, got, want)
		}
	}
	// IDs spread evenly: each tenth of the range holds about a tenth of them.
	const total = 200_000
	var buckets [10]int
	for i := range total {
		position := Position(fmt.Sprintf("01a14a2c-7ee1-7ad7-bbf6-%012x", i))
		if position < 0 || position >= 1 {
			t.Fatalf("position %v is outside [0, 1)", position)
		}
		buckets[int(position*10)]++
	}
	for i, count := range buckets {
		if count < total/10*97/100 || count > total/10*103/100 {
			t.Fatalf("bucket %d holds %d of %d IDs", i, count, total)
		}
	}
}

// One receiver gets a record exactly when one of the destinations that name it
// would, whatever their samples, and with content when any of them sends it.
func TestCombineSendsWhatAnyDuplicateSends(t *testing.T) {
	random := rand.New(rand.NewPCG(7, 19))
	randomSample := func() *Sample {
		switch random.IntN(4) {
		case 0:
			return nil
		case 1:
			rate := 1 - random.Float64()
			return &Sample{rate, rate, rate, rate, rate}
		}
		var sample Sample
		for sample.validate() != nil {
			for i := range sample {
				if random.IntN(2) == 0 {
					sample[i] = []float64{1, 1 - random.Float64(), 0.5, 0.001}[random.IntN(4)]
				} else {
					sample[i] = 0
				}
			}
		}
		return &sample
	}
	off := false
	for range 2000 {
		var configs []*Config
		var parts []Destination
		for range 1 + random.IntN(4) {
			d := Destination{URL: "https://receiver.example/", Sample: randomSample()}
			if random.IntN(2) == 0 {
				d.Content = &off
			}
			parts = append(parts, d)
			// Duplicates meet inside one policy and across policies.
			if len(configs) > 0 && random.IntN(2) == 0 {
				last := configs[len(configs)-1]
				last.Destinations = append(last.Destinations, d)
			} else {
				configs = append(configs, &Config{Destinations: []Destination{d}})
			}
		}
		combined, err := Combine(configs...)
		if err != nil || len(combined.Destinations) != 1 {
			t.Fatalf("combined = %+v, %v", combined, err)
		}
		merged := combined.Destinations[0]
		if merged.Validate() != nil {
			t.Fatalf("combined sample %v is not valid", merged.Sample)
		}
		content := false
		for _, part := range parts {
			content = content || part.SendsContent()
		}
		if merged.SendsContent() != content {
			t.Fatalf("content = %v, want %v", merged.SendsContent(), content)
		}
		for range 50 {
			position := random.Float64()
			for _, outcome := range Outcomes {
				want := false
				for _, part := range parts {
					want = want || position < part.Rate(outcome)
				}
				if got := position < merged.Rate(outcome); got != want {
					t.Fatalf("position %v, outcome %s: combined %v sends %v, parts %+v send %v", position, outcome, merged.Sample, got, parts, want)
				}
			}
		}
		// Combining again changes nothing, and the parts keep their samples.
		again, err := Combine(combined, combined)
		if err != nil || len(again.Destinations) != 1 || (again.Destinations[0].Sample == nil) != (merged.Sample == nil) || (merged.Sample != nil && *again.Destinations[0].Sample != *merged.Sample) {
			t.Fatalf("combined twice = %+v, %v", again, err)
		}
	}
	// Every outcome in full is a destination without a sample, as the editor shows it.
	combined, err := Combine(&Config{Destinations: []Destination{
		{URL: "https://receiver.example/", Sample: &Sample{1, 1, 0, 0, 0}},
		{URL: "https://receiver.example/", Sample: &Sample{0, 0, 1, 1, 1}},
	}})
	if err != nil || combined.Destinations[0].Sample != nil {
		t.Fatalf("combined = %+v, %v", combined, err)
	}
	// A sample does not make another receiver: the URL and headers do.
	first := Destination{URL: "https://receiver.example/", Sample: &Sample{0.5, 0, 0, 0, 0}}
	shared := &Config{Destinations: []Destination{first}}
	if _, err := Combine(shared, &Config{Destinations: []Destination{{URL: "https://receiver.example/", Sample: &Sample{0, 1, 0, 0, 0}}}}); err != nil {
		t.Fatal(err)
	}
	if first.Identity() != (Destination{URL: "https://receiver.example/"}).Identity() || *shared.Destinations[0].Sample != (Sample{0.5, 0, 0, 0, 0}) {
		t.Fatal("combining changed a policy's own destination")
	}
}
