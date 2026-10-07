package catalog

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
)

// A snapshot owns immutable execution facts. Decode repeated maps once instead
// of expanding them for every deployment. Pools disappear after loading;
// nothing is retained across catalog releases. Signed artifact bytes stay exact.
func decodeCompiledCatalog(data []byte) (compiledCatalog, error) {
	var catalog compiledCatalog
	err := json.Unmarshal(data, &catalog, json.RejectUnknownMembers(true),
		json.WithUnmarshalers(json.JoinUnmarshalers(
			sharedJSON[map[string]FileInputs](),
			sharedJSON[map[string]DataHandling](),
			sharedJSON[Pricing](),
		)),
	)
	return catalog, err
}

func sharedJSON[T any]() *json.Unmarshalers {
	pool := make(map[string]T)
	return json.UnmarshalFromFunc(func(decoder *jsontext.Decoder, destination *T) error {
		raw, err := decoder.ReadValue()
		if err != nil {
			return err
		}
		if existing, ok := pool[string(raw)]; ok {
			*destination = existing
			return nil
		}
		var value T
		if err := json.Unmarshal(raw, &value, json.RejectUnknownMembers(true)); err != nil {
			return err
		}
		pool[string(raw)] = value
		*destination = value
		return nil
	})
}
