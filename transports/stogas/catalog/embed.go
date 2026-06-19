package catalog

import _ "embed"

//go:embed generated/catalog.json
var embeddedCatalogJSON []byte
