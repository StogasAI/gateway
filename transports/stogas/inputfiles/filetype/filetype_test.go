package filetype

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"
)

// The dashboard's policy schema names the same media types, and reads them from this file.
func TestMediaTypesMatchTestdata(t *testing.T) {
	raw, err := os.ReadFile("testdata/media-types.json")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string][]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"office": slices.Concat(Documents, Spreadsheets, Presentations), "textApplication": textApplicationTypes}
	if !reflect.DeepEqual(got, want) {
		expected, _ := json.MarshalIndent(want, "", "\t")
		t.Fatalf("testdata/media-types.json differs from the lists; want:\n%s", expected)
	}
}

func TestFamilyOf(t *testing.T) {
	for mediaType, want := range map[string]Family{
		"text/plain": Text, "text/x-anything": Text, "application/json": Text, "application/ld+json": Text, "image/svg+xml": Text,
		"application/vnd.oasis.opendocument.text": Office, "application/vnd.ms-excel.sheet.macroenabled.12": Office,
		"application/pdf": "", "application/zip": "", "application/msword": "", "application/rtf": "", "image/png": "", "": "",
	} {
		if got := FamilyOf(mediaType); got != want {
			t.Errorf("%q is %q, want %q", mediaType, got, want)
		}
	}
	for _, mediaType := range textApplicationTypes {
		if FamilyOf(mediaType) != Text {
			t.Errorf("%q is not text", mediaType)
		}
	}
}
