package rawjson

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestContainersRejectAmbiguousMalformedAndWrongRoots(t *testing.T) {
	for _, source := range []string{`null`, `{}`, `[1,]`, `[1] {}`, `[{"x":1,"x":2}]`} {
		if _, err := Array([]byte(source)); err == nil {
			t.Fatalf("accepted array %s", source)
		}
	}
	for _, source := range []string{`null`, `[]`, `{"x":1,}`, `{} []`, `{"x":1,"x":2}`} {
		if _, err := Object([]byte(source)); err == nil {
			t.Fatalf("accepted object %s", source)
		}
	}
}

func FuzzBorrowedContainersPreserveValues(f *testing.F) {
	for _, source := range []string{` {"nested": [null, {"text":"\u00e9🙂"}], "number": 1e999999999 } `, ` ["", [], {"escaped\"key":false}] `, `[]`, `{}`} {
		f.Add([]byte(source))
	}
	f.Fuzz(func(t *testing.T, source []byte) {
		before := bytes.Clone(source)
		if array, err := Array(source); err == nil {
			var reference []json.RawMessage
			if err := json.Unmarshal(source, &reference); err != nil || !reflect.DeepEqual(array, reference) {
				t.Fatalf("array differs: %v", err)
			}
			for _, value := range array {
				_ = append(value, '!')
			}
		}
		if object, err := Object(source); err == nil {
			var reference map[string]json.RawMessage
			if err := json.Unmarshal(source, &reference); err != nil || !reflect.DeepEqual(object, reference) {
				t.Fatalf("object differs: %v", err)
			}
			for _, value := range object {
				_ = append(value, '!')
			}
		}
		if !bytes.Equal(source, before) {
			t.Fatal("decoding or appending to a value mutated the source")
		}
	})
}
