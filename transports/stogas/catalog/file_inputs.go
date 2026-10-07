package catalog

import (
	"errors"
	"regexp"
)

// FileInputs describes native document content parts, separately from image
// and audio parts. The compiler resolves route facts and deployment overrides,
// including provider preprocessing; request-time text extraction runs first.
type FileInputs struct {
	MediaTypes []string `json:"mediaTypes"`
	Extensions []string `json:"extensions"`
}

var fileMediaType = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$`)
var fileExtension = regexp.MustCompile(`^\.[a-z0-9][a-z0-9._+-]*$`)

func validateFileInputs(value FileInputs) error {
	for _, field := range []struct {
		values  []string
		pattern *regexp.Regexp
	}{{value.MediaTypes, fileMediaType}, {value.Extensions, fileExtension}} {
		if field.values == nil {
			return errors.New("native file formats must be explicit arrays")
		}
		for i, entry := range field.values {
			if !field.pattern.MatchString(entry) || (i > 0 && field.values[i-1] >= entry) {
				return errors.New("native file formats must be sorted, unique and lowercase")
			}
		}
	}
	if len(value.MediaTypes) == 0 && len(value.Extensions) != 0 {
		return errors.New("file extensions require native media types")
	}
	return nil
}
