package exportconfig

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"reflect"
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

// Content reads true, false or a share, and writes back what it read.
func TestContentReadsEveryRecordNoneOrAShare(t *testing.T) {
	for raw, want := range map[string]Content{
		`true`:                        {1, 1, 1, 1, 1},
		`false`:                       {},
		`0.25`:                        {0.25, 0.25, 0.25, 0.25, 0.25},
		`{"failed":1,"rejected":0.5}`: {0, 1, 0, 0.5, 0},
	} {
		var d Destination
		if err := json.Unmarshal([]byte(`{"url":"https://receiver.example/","content":`+raw+`}`), &d); err != nil || d.Validate() != nil || *d.Content != want {
			t.Fatalf("content %s = %v, %v", raw, d.Content, err)
		}
		encoded, err := json.Marshal(d)
		if err != nil || string(encoded) != `{"url":"https://receiver.example/","content":`+raw+`}` {
			t.Fatalf("content %s was written as %s, %v", raw, encoded, err)
		}
	}
	for _, raw := range []string{`null`, `0`, `1.5`, `"true"`, `[true]`, `{}`, `{"failure":1}`, `{"failed":0}`, `{"failed":true}`} {
		var d Destination
		if err := json.Unmarshal([]byte(`{"url":"https://receiver.example/","content":`+raw+`}`), &d); err == nil && d.Content != nil {
			t.Fatalf("content %s was accepted as %v", raw, d.Content)
		}
	}
	var content Content
	if json.Unmarshal([]byte(`null`), &content) == nil {
		t.Fatal("a null content was accepted")
	}
	for _, content := range []Content{{math.NaN(), 1, 1, 1, 1}, {1, 1, 1, 1, 1.5}, {-0.1, 1, 1, 1, 1}} {
		if (&Destination{URL: "https://receiver.example/", Content: &content}).Validate() == nil {
			t.Fatalf("content %v was accepted", content)
		}
	}
	// A destination gets bodies only with a record that it gets.
	d := Destination{Sample: &Sample{0.2, 1, 0, 0, 0}, Content: &Content{0.5, 0.5, 1, 0, 0}}
	for outcome, want := range map[string]float64{"success": 0.2, "failed": 0.5, "cancelled": 0, "rejected": 0, "unknown": 0, "": 0} {
		if got := d.ContentRate(outcome); got != want {
			t.Fatalf("content rate of %q = %v, want %v", outcome, got, want)
		}
	}
	if d.ContentReach() != 0.5 || (Destination{}).ContentReach() != 1 || (Destination{Content: &Content{}}).ContentReach() != 0 {
		t.Fatal("content reach is the highest rate of bodies")
	}
}

// One receiver gets a record exactly when one of the destinations that name it
// would, whatever their samples, and with bodies exactly when one that gets the
// record sends them.
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
	for range 2000 {
		var configs []*Config
		var parts []Destination
		for range 1 + random.IntN(4) {
			d := Destination{URL: "https://receiver.example/", Sample: randomSample()}
			switch random.IntN(3) {
			case 0:
				d.Content = &Content{}
			case 1:
				d.Content = (*Content)(randomSample())
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
		for range 50 {
			position := random.Float64()
			for _, outcome := range Outcomes {
				want, wantBodies := false, false
				for _, part := range parts {
					want = want || position < part.Rate(outcome)
					wantBodies = wantBodies || position < part.ContentRate(outcome)
				}
				if got := position < merged.Rate(outcome); got != want {
					t.Fatalf("position %v, outcome %s: combined %v sends %v, parts %+v send %v", position, outcome, merged.Sample, got, parts, want)
				}
				if got := position < merged.ContentRate(outcome); got != wantBodies {
					t.Fatalf("position %v, outcome %s: combined %v sends bodies %v, parts %+v send %v", position, outcome, merged.Content, got, parts, wantBodies)
				}
			}
		}
		// Combining again changes nothing, and what it wrote reads back the same.
		again, err := Combine(combined, combined)
		if err != nil || len(again.Destinations) != 1 || !reflect.DeepEqual(again.Destinations[0], merged) {
			t.Fatalf("combined twice = %+v, %v", again, err)
		}
		encoded, err := json.Marshal(merged)
		var read Destination
		if err != nil || json.Unmarshal(encoded, &read) != nil || read.Validate() != nil {
			t.Fatalf("combined %s does not read back: %v", encoded, err)
		}
		records, bodies := merged.shares()
		readRecords, readBodies := read.shares()
		if records != readRecords || bodies != readBodies {
			t.Fatalf("combined %s read back as %v and %v, want %v and %v", encoded, readRecords, readBodies, records, bodies)
		}
	}
	// The record for every request with bodies for failures only, said as two
	// destinations, is one destination that a policy can write.
	metadata, failures := Destination{URL: "https://receiver.example/", Content: &Content{}}, Destination{URL: "https://receiver.example/", Sample: &Sample{0, 1, 0, 1, 0}}
	both, err := Combine(&Config{Destinations: []Destination{metadata}}, &Config{Destinations: []Destination{failures}})
	if err != nil {
		t.Fatal(err)
	}
	if encoded, _ := json.Marshal(both.Destinations[0]); string(encoded) != `{"url":"https://receiver.example/","content":{"failed":1,"rejected":1}}` {
		t.Fatalf("combined = %s", encoded)
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

func TestFormatNamesAKnownShape(t *testing.T) {
	for raw, valid := range map[string]bool{
		`{"url":"https://receiver.example/"}`:                                     true,
		`{"url":"https://receiver.example/v1/traces","format":"otlp-genai-1.41"}`: true,
		`{"url":"https://receiver.example/v1/traces","format":"otlp-genai-0.1"}`:  true,
		`{"url":"https://receiver.example/","format":"otlp"}`:                     false,
		`{"url":"https://receiver.example/","format":"otlp-genai-0.1.0"}`:         false,
		`{"url":"https://receiver.example/","format":"json"}`:                     false,
		`{"url":"https://receiver.example/","format":"OTLP-GenAI-1.41"}`:          false,
	} {
		var d Destination
		if err := json.Unmarshal([]byte(raw), &d); err != nil || (d.Validate() == nil) != valid {
			t.Errorf("%s: valid = %v, want %v", raw, d.Validate() == nil, valid)
		}
	}
	// One URL that takes three formats is three receivers, and each gets its record.
	record := Destination{URL: "https://receiver.example/"}
	trace := Destination{URL: "https://receiver.example/", Format: FormatOTLPGenAI141}
	latest := Destination{URL: "https://receiver.example/", Format: FormatOTLPGenAI01}
	combined, err := Combine(&Config{Destinations: []Destination{record, latest}}, &Config{Destinations: []Destination{trace, trace}})
	if err != nil || len(combined.Destinations) != 3 || record.Identity() == trace.Identity() || trace.Identity() == latest.Identity() {
		t.Fatalf("combined = %+v, %v", combined, err)
	}
}
