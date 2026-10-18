package catalog

import "errors"

// DocumentFormats lists the file types a route's provider reads natively from a document
// part. Image and audio parts follow the deployment's input modalities; request-time text
// extraction runs first.
type DocumentFormats struct {
	MediaTypes []string `json:"mediaTypes"`
	Extensions []string `json:"extensions"`
}

// The policy vocabulary pass checks the form of each entry.
func validateDocumentFormats(value DocumentFormats) error {
	for _, values := range [][]string{value.MediaTypes, value.Extensions} {
		if values == nil {
			return errors.New("document formats must be explicit arrays")
		}
		for i := 1; i < len(values); i++ {
			if values[i-1] >= values[i] {
				return errors.New("document formats must be sorted and unique")
			}
		}
	}
	if len(value.MediaTypes) == 0 && len(value.Extensions) != 0 {
		return errors.New("file extensions require document media types")
	}
	return nil
}
