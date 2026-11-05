package stogas

import "github.com/maximhq/bifrost/transports/stogas/location"

// testPlaces are the places that tests name, as a catalog lists them.
var testPlaces = func() *location.Places {
	places, err := location.Read(map[string][]string{
		"world":         nil,
		"europe":        {"world"},
		"eu":            {"europe"},
		"SE":            {"eu"},
		"CH":            {"europe"},
		"north-america": {"world"},
		"US":            {"north-america"},
		"JP":            {"world"},
	})
	if err != nil {
		panic(err)
	}
	return places
}()
