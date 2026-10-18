package catalog

import (
	"errors"
	"regexp"
)

// DocumentFormats lists the file types a route's provider reads natively from a document
// part. Image and audio parts follow the deployment's input modalities; request-time text
// extraction runs first.
type DocumentFormats struct {
	MediaTypes []string `json:"mediaTypes"`
	Extensions []string `json:"extensions"`
}

var fileMediaType = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$`)
var fileExtension = regexp.MustCompile(`^\.[a-z0-9][a-z0-9._+-]*$`)

func validateDocumentFormats(value DocumentFormats) error {
	for _, field := range []struct {
		values  []string
		pattern *regexp.Regexp
	}{{value.MediaTypes, fileMediaType}, {value.Extensions, fileExtension}} {
		if field.values == nil {
			return errors.New("document formats must be explicit arrays")
		}
		for i, entry := range field.values {
			if !field.pattern.MatchString(entry) || (i > 0 && field.values[i-1] >= entry) {
				return errors.New("document formats must be sorted, unique and lowercase")
			}
		}
	}
	if len(value.MediaTypes) == 0 && len(value.Extensions) != 0 {
		return errors.New("file extensions require document media types")
	}
	return nil
}
