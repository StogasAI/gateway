package stogashttp

var stogasResponseFields = map[string]bool{
	"latency":                   true,
	"model_deployment":          true,
	"model_requested":           true,
	"provider":                  true,
	"provider_response_headers": true,
	"raw_request":               true,
	"raw_response":              true,
}

func allowsStogasResponseField(name string) bool {
	return stogasResponseFields[name]
}
