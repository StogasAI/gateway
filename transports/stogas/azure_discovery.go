package stogas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"golang.org/x/sync/errgroup"
)

// Only a gateway can open a customer-encrypted Azure credential, so a gateway discovers its
// targets as Control discovers a stored credential's: the same reads of Azure Resource Manager,
// bounds, targets and messages, so the dashboard shows both kinds alike. The cases in
// testdata/azure-discovery run against both implementations.
const (
	armInstantAPIVersion     = "2026-01-15-preview"
	armLocationsAPIVersion   = "2022-12-01"
	armPermissionsAPIVersion = "2022-04-01"
	// Control's bounds: each read, the reads in flight, and the Foundry projects and targets.
	azureDiscoveryRequestTimeout = 12 * time.Second
	azureDiscoveryConcurrency    = 8
	azureDiscoveryMaxProjects    = 2_048
	azureDiscoveryMaxBindings    = 20_000
	// A discovery finishes within the 30-second claim that it holds for the fleet.
	azureDiscoveryTimeout = 25 * time.Second
	azureInstantLocation  = "westus3"

	azureDiscoveryUnavailable = "Could not inspect Azure resources. Try again."
	azureAccountDenied        = "This application cannot read the account. Check the account ID and give the application the Foundry User role on the account."
	// The targets stay, because a new role takes minutes to appear and roles from groups are unverified.
	azureRoleMissing    = "The application has no data role on this account, so requests to its deployments fail. Give it the Foundry User role on the account."
	azureAppRejected    = "Azure did not accept this tenant, client ID, and client secret"
	azureAppUnavailable = "Could not authenticate with Azure. Try again."
)

var (
	azureAccountProblems = map[string]string{
		"endpoint":  "Azure lists no endpoint on this account’s custom subdomain, so requests cannot sign in.",
		"network":   "This account admits only selected networks or private endpoints. Allow access from all networks to use it.",
		"subdomain": "This account has no custom subdomain, which Entra sign-in needs. Add one to use the account.",
	}
	azureGeographyLocations = map[string]string{
		"asia pacific": "apac", "asia": "apac", "australia": "AU", "austria": "AT", "belgium": "BE",
		"brazil": "BR", "canada": "CA", "chile": "CL", "denmark": "DK", "europe": "europe",
		"finland": "FI", "france": "FR", "germany": "DE", "india": "IN", "indonesia": "ID",
		"israel": "IL", "italy": "IT", "japan": "JP", "korea": "KR", "malaysia": "MY", "mexico": "MX",
		"new zealand": "NZ", "norway": "NO", "poland": "PL", "qatar": "QA", "saudi arabia": "SA",
		"singapore": "SG", "south africa": "ZA", "south korea": "KR", "spain": "ES", "sweden": "SE",
		"switzerland": "CH", "taiwan": "TW", "uae": "AE", "united arab emirates": "AE",
		"united kingdom": "GB", "united states": "US", "usa": "US",
	}
	azureProjectNamePattern  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,63}$`)
	azureEndpointLabel       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	azureInstantVersion      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	azureAzureHostedFormats  = map[string]bool{"deepseek": true, "moonshotai": true, "openai": true, "openai-oss": true}
	azureDiscoveryDateLayout = []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02T15:04", "2006-01-02"}
)

// azureDiscoveryError is why a discovery stopped, in the words that Control records. Rejected marks
// a problem with the application or the account, which trying again does not fix.
type azureDiscoveryError struct {
	message  string
	rejected bool
}

func (e *azureDiscoveryError) Error() string { return e.message }

func azureDiscoveryRejected(message string) error {
	return &azureDiscoveryError{message: message, rejected: true}
}

func azureDiscoveryFailed(message string) error {
	return &azureDiscoveryError{message: message}
}

// azureDiscoveryMessage is the message that a check records for err.
func azureDiscoveryMessage(err error) string {
	var discovery *azureDiscoveryError
	if errors.As(err, &discovery) {
		return discovery.message
	}
	return azureDiscoveryUnavailable
}

// azureDiscoveredBinding is a target that a deployment or an Instant project makes, as
// azure_save_discovery reads it.
type azureDiscoveredBinding struct {
	// The deployment's version upgrade option, empty when Azure left it out or for an Instant
	// target, which names its version.
	VersionUpgrade       string     `json:"versionUpgrade"`
	DeploymentName       string     `json:"deploymentName"`
	DeploymentResourceID string     `json:"deploymentResourceId"`
	DeploymentType       string     `json:"deploymentType"`
	Endpoint             string     `json:"endpoint"`
	Hosting              string     `json:"hosting"`
	ProcessingLocation   string     `json:"processingLocation"`
	ModelDeprecationAt   *time.Time `json:"modelDeprecationAt"`
	ModelFormat          string     `json:"modelFormat"`
	ModelHostedOn        *string    `json:"modelHostedOn"`
	ModelName            string     `json:"modelName"`
	ModelPublisher       *string    `json:"modelPublisher"`
	ModelVersion         string     `json:"modelVersion"`
	SkuName              string     `json:"skuName"`
	StorageLocation      string     `json:"storageLocation"`
	TokenScope           string     `json:"tokenScope"`
}

// azureDiscovery is what a discovery found: the targets, every deployment that the account lists,
// a problem that leaves the targets in place, and the account's name.
type azureDiscovery struct {
	Bindings     []azureDiscoveredBinding
	Deployments  []billing.AzureDeployment
	CheckError   string
	DiscoveredAt time.Time
	Name         string
}

// armReads makes a discovery's reads of Azure Resource Manager, a few at a time, each bounded in
// time and size, and never follows a redirect.
type armReads struct {
	client *http.Client
	token  string
	slots  chan struct{}
}

func newARMReads(client *http.Client, token string) *armReads {
	return &armReads{client: client, token: token, slots: make(chan struct{}, azureDiscoveryConcurrency)}
}

// data reads one resource. Azure answers 401, 403 or 404 when the application cannot read a
// resource or it does not exist, which denied names.
func (r *armReads) data(ctx context.Context, resource string, denied string) (json.RawMessage, error) {
	select {
	case r.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, azureDiscoveryFailed(azureDiscoveryUnavailable)
	}
	defer func() { <-r.slots }()
	ctx, cancel := context.WithTimeout(ctx, azureDiscoveryRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resource, nil)
	if err != nil {
		return nil, azureDiscoveryFailed(azureDiscoveryUnavailable)
	}
	request.Header.Set("Authorization", "Bearer "+r.token)
	request.Header.Set("Accept", "application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, azureDiscoveryFailed(azureDiscoveryUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, armMaxResponseBytes))
		switch response.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return nil, azureDiscoveryRejected(denied)
		}
		return nil, azureDiscoveryFailed(azureDiscoveryUnavailable)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, armMaxResponseBytes+1))
	if err != nil {
		return nil, azureDiscoveryFailed("Azure returned an invalid response")
	}
	if len(body) > armMaxResponseBytes {
		return nil, azureDiscoveryFailed("Azure returned too much management data")
	}
	if !json.Valid(body) {
		return nil, azureDiscoveryFailed("Azure returned an invalid response")
	}
	return body, nil
}

// pages reads every page of a listing, up to armMaxPages and the bound on targets.
func (r *armReads) pages(ctx context.Context, first string, denied string) ([]json.RawMessage, error) {
	var items []json.RawMessage
	next := first
	for page := 0; next != "" && page < armMaxPages; page++ {
		body, err := r.data(ctx, next, denied)
		if err != nil {
			return nil, err
		}
		listing, ok := armObject(body)
		if !ok {
			return nil, azureDiscoveryFailed("Azure returned invalid management data")
		}
		// A listing without a value lists nothing.
		var values []json.RawMessage
		if raw, present := listing["value"]; present {
			if raw = bytes.TrimSpace(raw); len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &values) != nil {
				return nil, azureDiscoveryFailed("Azure returned invalid management data")
			}
		}
		link, state := armString(listing, "nextLink")
		if state == armOther || state == armText && !armURL(link) {
			return nil, azureDiscoveryFailed("Azure returned invalid management data")
		}
		if items = append(items, values...); len(items) > azureDiscoveryMaxBindings {
			return nil, azureDiscoveryRejected("Azure discovery returned too many resources")
		}
		next = ""
		if state == armText {
			if next, err = armNextLink(link); err != nil {
				return nil, azureDiscoveryFailed("Azure returned an invalid continuation URL")
			}
		}
	}
	if next != "" {
		return nil, azureDiscoveryFailed("Azure discovery returned too many pages")
	}
	return items, nil
}

func armResource(path string, version string) string {
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return "https://" + armHost + path + separator + "api-version=" + version
}

// armField is how an object holds a field: not at all, as null, as a string, or as anything else.
type armField int

const (
	armAbsent armField = iota
	armNull
	armText
	armOther
)

func armObject(value json.RawMessage) (map[string]json.RawMessage, bool) {
	value = bytes.TrimSpace(value)
	if len(value) == 0 || value[0] != '{' {
		return nil, false
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(value, &object) != nil {
		return nil, false
	}
	return object, true
}

func armString(object map[string]json.RawMessage, key string) (string, armField) {
	raw, present := object[key]
	if !present {
		return "", armAbsent
	}
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		return "", armNull
	}
	var text string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &text) != nil {
		return "", armOther
	}
	return text, armText
}

// armRequiredString reads a field that must be a non-empty string.
func armRequiredString(object map[string]json.RawMessage, key string) (string, bool) {
	text, state := armString(object, key)
	return text, state == armText && text != ""
}

// armOptionalString reads a field that may be absent, or a string; nullable also admits null.
func armOptionalString(object map[string]json.RawMessage, key string, nullable bool) (string, bool) {
	text, state := armString(object, key)
	return text, state == armAbsent || state == armText || nullable && state == armNull
}

// armURL reports whether text is an absolute URL, as Control's schema requires of a continuation.
func armURL(text string) bool {
	parsed, err := url.Parse(strings.TrimSpace(text))
	return err == nil && parsed.Scheme != "" && (parsed.Host != "" || parsed.Opaque != "")
}

// azureModelIdentity is a model's format, name and version, each a non-empty string.
type azureModelIdentity struct {
	format, name, version string
}

func armModelIdentity(value json.RawMessage) (azureModelIdentity, map[string]json.RawMessage, bool) {
	object, ok := armObject(value)
	if !ok {
		return azureModelIdentity{}, nil, false
	}
	format, formatOK := armRequiredString(object, "format")
	name, nameOK := armRequiredString(object, "name")
	version, versionOK := armRequiredString(object, "version")
	return azureModelIdentity{format, name, version}, object, formatOK && nameOK && versionOK
}

func (m azureModelIdentity) key() string {
	return strings.ToLower(trimJS(m.format)) + "\x00" + strings.ToLower(trimJS(m.name)) + "\x00" + strings.ToLower(trimJS(m.version))
}

// azureModelMetadata is what Azure says about a model: when it retires, who hosts it, whether
// Instant serves it, and its publisher.
type azureModelMetadata struct {
	deprecationAt *time.Time
	hostedOn      *string
	instant       bool
	publisher     *string
}

func (m azureModelMetadata) equal(other azureModelMetadata) bool {
	return equalOptional(m.hostedOn, other.hostedOn) && m.instant == other.instant &&
		equalOptional(m.publisher, other.publisher) &&
		(m.deprecationAt == nil) == (other.deprecationAt == nil) &&
		(m.deprecationAt == nil || m.deprecationAt.Equal(*other.deprecationAt))
}

func equalOptional(left, right *string) bool {
	return (left == nil) == (right == nil) && (left == nil || *left == *right)
}

// azureOptionalText is a trimmed string value, or nil for anything else or an empty one.
func azureOptionalText(object map[string]json.RawMessage, key string) *string {
	text, state := armString(object, key)
	if text = trimJS(text); state != armText || text == "" {
		return nil
	}
	return &text
}

func azureModelMetadataOf(model map[string]json.RawMessage) azureModelMetadata {
	capabilities, _ := armObject(model["capabilities"])
	deprecation, _ := armObject(model["deprecation"])
	metadata := azureModelMetadata{
		hostedOn:  azureOptionalText(model, "hostedOn"),
		publisher: azureOptionalText(model, "publisher"),
	}
	if metadata.hostedOn == nil {
		metadata.hostedOn = azureOptionalText(capabilities, "hostedOn")
	}
	if inference := azureOptionalText(deprecation, "inference"); inference != nil {
		metadata.deprecationAt = azureDiscoveryDate(*inference)
	}
	metadata.instant = strings.ToLower(trimJS(azureCapabilityText(capabilities["instant"]))) == "true"
	return metadata
}

// azureCapabilityText is a capability as JavaScript's String() writes it: a string as itself and
// true as "true". Only "true" matters, so other values become empty.
func azureCapabilityText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("true")) {
		return "true"
	}
	var text string
	if len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, &text) == nil {
		return text
	}
	return ""
}

// azureDiscoveryDate reads a retirement date as JavaScript's Date.parse reads Azure's ISO dates,
// with a date or a time without an offset in UTC, to the millisecond.
func azureDiscoveryDate(text string) *time.Time {
	for _, layout := range azureDiscoveryDateLayout {
		if parsed, err := time.Parse(layout, text); err == nil {
			parsed = parsed.UTC().Truncate(time.Millisecond)
			return &parsed
		}
	}
	return nil
}

// azureRegionalModel is a model that the account's region offers, with its trimmed identity.
type azureRegionalModel struct {
	azureModelMetadata
	format, name, version string
}

func azureModelHosting(format string, metadata azureModelMetadata) string {
	switch normalized := strings.ToLower(trimJS(format)); {
	case normalized == "anthropic":
		if metadata.hostedOn == nil {
			// Azure's older Anthropic-hosted model records do not include hostedOn.
			return "anthropic"
		}
		if hostedOn := strings.ToLower(*metadata.hostedOn); hostedOn == "azure" || hostedOn == "anthropic" {
			return hostedOn
		}
		return ""
	case normalized == "fireworks":
		return "fireworks"
	case azureAzureHostedFormats[normalized]:
		return "azure"
	}
	return ""
}

type azureLocation struct{ geography, geographyGroup string }

func azureStorageLocation(geography string) string {
	if location, ok := azureGeographyLocations[strings.ToLower(trimJS(geography))]; ok {
		return location
	}
	return "unknown"
}

// azureDiscoveryContext is what every target of the account shares.
type azureDiscoveryContext struct {
	accountID       string
	accountLocation string
	models          map[string]azureRegionalModel
	modelOrder      []string
	bindings        int
	discoveredAt    time.Time
	foundry         string
	openAI          string
	locations       map[string]azureLocation
}

func (c *azureDiscoveryContext) storageLocation() string {
	return azureStorageLocation(c.locations[strings.ToLower(trimJS(c.accountLocation))].geography)
}

func (c *azureDiscoveryContext) append(bindings []azureDiscoveredBinding, binding azureDiscoveredBinding) ([]azureDiscoveredBinding, error) {
	if c.bindings++; c.bindings > azureDiscoveryMaxBindings {
		return nil, azureDiscoveryRejected("Azure discovery returned too many deployments")
	}
	return append(bindings, binding), nil
}

// placement is where a deployment's SKU processes and stores requests.
func (c *azureDiscoveryContext) placement(skuName string, hosting string) (deploymentType, processing, storage string, ok bool) {
	sku := strings.ToLower(trimJS(skuName))
	external := hosting != "azure"
	storage = "unknown"
	if !external {
		storage = c.storageLocation()
	}
	if sku == "globalstandard" {
		processing = "unknown"
		if !external {
			processing = "world"
		}
		return "global_standard", processing, storage, true
	}
	if sku != "datazonestandard" {
		return "", "", "", false
	}
	switch strings.ToLower(trimJS(c.locations[strings.ToLower(trimJS(c.accountLocation))].geographyGroup)) {
	case "us":
		deploymentType, processing = "data_zone_standard_us", "US"
	case "europe":
		deploymentType, processing = "data_zone_standard_eu", "europe"
	case "asia pacific":
		deploymentType, processing = "data_zone_standard_apac", "apac"
	default:
		return "", "", "", false
	}
	if external {
		processing = "unknown"
	}
	return deploymentType, processing, storage, true
}

// azureAccountChild reads the identity of a deployment or project that the account lists: its
// name and lowercase resource ID, after checking that its ID names that account as its parent.
func azureAccountChild(value json.RawMessage, accountID string, kind string) (name string, resourceID string, err error) {
	object, ok := armObject(value)
	return azureAccountChildOf(object, ok, accountID, kind)
}

// azureAccountChildOf checks the identity of a child that is already decoded, or not an object.
func azureAccountChildOf(object map[string]json.RawMessage, ok bool, accountID string, kind string) (name string, resourceID string, err error) {
	id, idOK := armRequiredString(object, "id")
	reported, nameOK := armRequiredString(object, "name")
	if !ok || !idOK || !nameOK {
		return "", "", azureDiscoveryFailed("Azure returned an invalid resource identity")
	}
	trimmed := trimJS(id)
	name = trimmed[strings.LastIndexByte(trimmed, '/')+1:]
	valid := azureDeploymentNamePart.MatchString(name)
	if kind == "projects" {
		valid = azureProjectNamePattern.MatchString(name)
	}
	resourceID = strings.ToLower(trimmed)
	lowerName := strings.ToLower(name)
	reported = strings.ToLower(reported)
	account := accountID[strings.LastIndexByte(accountID, '/')+1:]
	if resourceID != accountID+"/"+kind+"/"+lowerName || !valid ||
		reported != lowerName && reported != account+"/"+lowerName {
		return "", "", azureDiscoveryFailed("Azure returned a resource outside its account")
	}
	return name, resourceID, nil
}

// azureAccountEndpoints finds the hosts that requests sign in to: the account's custom subdomain,
// or the host that Azure generates for an Azure OpenAI account created without one. A Foundry
// account without one lists a Foundry host named after the account that does not resolve, and
// regional hosts that refuse Entra sign-in. Gateways connect from public addresses that we do not
// publish, so Azure answers 403 after sign-in when an account admits only selected networks,
// private endpoints, or a network security perimeter. It returns a problem when there is none.
func azureAccountEndpoints(kind string, properties map[string]json.RawMessage, endpoints []armEntry) (foundry, openAI, problem string) {
	publicAccess, _ := armString(properties, "publicNetworkAccess")
	if publicAccess = strings.ToLower(trimJS(publicAccess)); publicAccess == "" {
		publicAccess = "enabled"
	}
	acls, _ := armObject(properties["networkAcls"])
	defaultAction, _ := armString(acls, "defaultAction")
	if defaultAction = strings.ToLower(trimJS(defaultAction)); defaultAction == "" {
		defaultAction = "allow"
	}
	if publicAccess != "enabled" || defaultAction != "allow" {
		return "", "", "network"
	}
	subdomain, _ := armString(properties, "customSubDomainName")
	subdomain = strings.ToLower(trimJS(subdomain))
	generated := subdomain == "" && strings.ToLower(trimJS(kind)) == "openai"
	endpoint := func(name, suffix string) string {
		for _, entry := range endpoints {
			if strings.ToLower(trimJS(entry.key)) != name {
				continue
			}
			host, ok := azureEndpointHost(entry.value)
			if !ok || !strings.HasSuffix(host, suffix) {
				return ""
			}
			label := strings.TrimSuffix(host, suffix)
			own := label == subdomain
			if subdomain == "" {
				own = generated && suffix == ".openai.azure.com"
			}
			if own && azureEndpointLabel.MatchString(label) {
				return "https://" + host
			}
			return ""
		}
		return ""
	}
	foundry = endpoint("ai foundry api", ".services.ai.azure.com")
	if foundry == "" {
		foundry = endpoint("azure ai model inference api", ".services.ai.azure.com")
	}
	openAI = endpoint("openai language model instance api", ".openai.azure.com")
	if openAI == "" {
		openAI = endpoint("azure openai legacy api - latest moniker", ".openai.azure.com")
	}
	if foundry != "" || openAI != "" {
		return foundry, openAI, ""
	}
	if subdomain != "" {
		return "", "", "endpoint"
	}
	return "", "", "subdomain"
}

// azureEndpointHost reads an endpoint that is only an HTTPS origin, as a WHATWG URL whose href is
// https://host/, and returns its lowercase host.
func azureEndpointHost(value string) (string, bool) {
	value = strings.TrimFunc(value, func(r rune) bool { return r <= 0x20 })
	value = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, value)
	parsed, err := url.Parse(value)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Port() != "" && parsed.Port() != "443" || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || strings.HasSuffix(value, "#") {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	return host, host != ""
}

// armEntry is one member of a JSON object, in the order that the object lists it.
type armEntry struct{ key, value string }

// armStringEntries reads an object of strings in order, keeping a repeated key's first place and
// last value as JavaScript does. It reports false for anything but an object of strings.
func armStringEntries(raw json.RawMessage) ([]armEntry, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, false
	}
	var entries []armEntry
	positions := map[string]int{}
	for decoder.More() {
		token, err := decoder.Token()
		key, isKey := token.(string)
		if err != nil || !isKey {
			return nil, false
		}
		var value string
		var rawValue json.RawMessage
		if decoder.Decode(&rawValue) != nil {
			return nil, false
		}
		if rawValue = bytes.TrimSpace(rawValue); len(rawValue) == 0 || rawValue[0] != '"' || json.Unmarshal(rawValue, &value) != nil {
			return nil, false
		}
		if position, seen := positions[key]; seen {
			entries[position].value = value
			continue
		}
		positions[key] = len(entries)
		entries = append(entries, armEntry{key, value})
	}
	return entries, true
}

// discoverAzure discovers the targets of the account accountID with an ARM token, as Control does.
func discoverAzure(ctx context.Context, client *http.Client, token string, accountID string, now time.Time) (*azureDiscovery, error) {
	ctx, cancel := context.WithTimeout(ctx, azureDiscoveryTimeout)
	defer cancel()
	if !azureAccountIDPattern.MatchString(accountID) {
		return nil, azureDiscoveryRejected("Use the resource ID of a Foundry or Azure OpenAI account")
	}
	reads := newARMReads(client, token)
	subscriptionID := strings.Split(accountID, "/")[2]
	accountBody, err := reads.data(ctx, armResource(accountID, armAPIVersion), azureAccountDenied)
	if err != nil {
		return nil, err
	}
	account, ok := armObject(accountBody)
	id, idOK := armRequiredString(account, "id")
	kind, kindOK := armRequiredString(account, "kind")
	location, locationOK := armRequiredString(account, "location")
	name, nameOK := armRequiredString(account, "name")
	properties, propertiesOK := armObject(account["properties"])
	if _, present := account["properties"]; !present {
		properties, propertiesOK = map[string]json.RawMessage{}, true
	}
	var endpoints []armEntry
	endpointsOK := true
	if raw, present := properties["endpoints"]; present {
		endpoints, endpointsOK = armStringEntries(raw)
	}
	_, subdomainOK := armOptionalString(properties, "customSubDomainName", false)
	_, publicOK := armOptionalString(properties, "publicNetworkAccess", true)
	aclsOK := true
	if raw, present := properties["networkAcls"]; present && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		acls, isObject := armObject(raw)
		_, actionOK := armOptionalString(acls, "defaultAction", true)
		aclsOK = isObject && actionOK
	}
	if !ok || !idOK || !kindOK || !locationOK || !nameOK || !propertiesOK || !endpointsOK || !subdomainOK ||
		!publicOK || !aclsOK || azureAccountResourceID(id) != accountID {
		return nil, azureDiscoveryFailed("Azure returned an invalid account")
	}
	normalizedKind := strings.ToLower(trimJS(kind))
	if normalizedKind != "aiservices" && normalizedKind != "openai" {
		return nil, azureDiscoveryRejected("This resource is not a Foundry or Azure OpenAI account")
	}
	foundry, openAI, problem := azureAccountEndpoints(kind, properties, endpoints)
	if problem != "" {
		return nil, azureDiscoveryRejected(azureAccountProblems[problem])
	}
	accountLocation := strings.ToLower(trimJS(location))
	supportsInstant := normalizedKind == "aiservices" && accountLocation == azureInstantLocation && foundry != ""

	var rawLocations, rawModels, rawDeployments, rawProjects []json.RawMessage
	var allowed map[string]bool
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() (err error) {
		rawLocations, err = reads.pages(groupCtx, "https://"+armHost+"/subscriptions/"+subscriptionID+"/locations?api-version="+armLocationsAPIVersion, azureAccountDenied)
		return err
	})
	group.Go(func() (err error) {
		rawModels, err = reads.pages(groupCtx, armResource("/subscriptions/"+subscriptionID+"/providers/Microsoft.CognitiveServices/locations/"+url.PathEscape(accountLocation)+"/models", armAPIVersion), azureAccountDenied)
		return err
	})
	group.Go(func() (err error) {
		rawDeployments, err = reads.pages(groupCtx, armResource(accountID+"/deployments", armAPIVersion), azureAccountDenied)
		return err
	})
	if supportsInstant {
		group.Go(func() (err error) {
			rawProjects, err = reads.pages(groupCtx, armResource(accountID+"/projects", armAPIVersion), azureAccountDenied)
			return err
		})
		group.Go(func() (err error) {
			allowed, err = azureInstantAllowList(groupCtx, reads, accountID)
			return err
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	if len(rawProjects) > azureDiscoveryMaxProjects {
		return nil, azureDiscoveryRejected("Azure discovery returned too many Foundry projects")
	}
	discovery := &azureDiscoveryContext{
		accountID:       accountID,
		accountLocation: accountLocation,
		models:          map[string]azureRegionalModel{},
		discoveredAt:    now,
		foundry:         foundry,
		openAI:          openAI,
		locations:       map[string]azureLocation{},
	}
	for _, value := range rawLocations {
		object, ok := armObject(value)
		locationName, nameOK := armRequiredString(object, "name")
		metadata, metadataOK := armObject(object["metadata"])
		_, metadataPresent := object["metadata"]
		geography, geographyOK := armOptionalString(metadata, "geography", false)
		zone, zoneOK := armOptionalString(metadata, "geographyGroup", false)
		if !ok || !nameOK || metadataPresent && (!metadataOK || !geographyOK || !zoneOK) {
			continue
		}
		discovery.locations[strings.ToLower(trimJS(locationName))] = azureLocation{geography, zone}
	}
	if err := discovery.readModels(rawModels); err != nil {
		return nil, err
	}
	bindings, deployments, names, err := discovery.deploymentBindings(rawDeployments)
	if err != nil {
		return nil, err
	}
	instant, err := discovery.instantBindings(rawProjects, names, allowed)
	if err != nil {
		return nil, err
	}
	result := &azureDiscovery{DiscoveredAt: now, Deployments: deployments, Name: trimJS(name)}
	// Instant targets take roles from their project, so only the account's own deployments need one.
	if len(bindings) > 0 {
		role, err := azureHasModelRole(ctx, reads, accountID)
		if err != nil {
			return nil, err
		}
		if !role {
			result.CheckError = azureRoleMissing
		}
	}
	result.Bindings = append(bindings, instant...)
	sort.SliceStable(result.Bindings, func(left, right int) bool {
		return azureBindingOrder(result.Bindings[left]) < azureBindingOrder(result.Bindings[right])
	})
	return result, nil
}

func azureBindingOrder(binding azureDiscoveredBinding) string {
	return strings.Join([]string{binding.DeploymentResourceID, binding.ModelFormat, binding.ModelName, binding.ModelVersion, binding.DeploymentType}, "\x00")
}

// azureAccountResourceID is an account ID as Control's schema keeps it, trimmed and lowercase, or
// empty when it names no account.
func azureAccountResourceID(value string) string {
	id := strings.ToLower(trimJS(value))
	if !azureAccountIDPattern.MatchString(id) {
		return ""
	}
	return id
}

func (c *azureDiscoveryContext) readModels(values []json.RawMessage) error {
	for _, value := range values {
		object, ok := armObject(value)
		if !ok {
			continue
		}
		identity, model, ok := armModelIdentity(object["model"])
		if !ok || !armModelMetadataValid(model) {
			continue
		}
		regional := azureRegionalModel{
			azureModelMetadata: azureModelMetadataOf(model),
			format:             trimJS(identity.format),
			name:               trimJS(identity.name),
			version:            trimJS(identity.version),
		}
		key := identity.key()
		if existing, seen := c.models[key]; seen {
			if !existing.equal(regional.azureModelMetadata) {
				return azureDiscoveryFailed("Azure returned conflicting model metadata")
			}
		} else {
			c.modelOrder = append(c.modelOrder, key)
		}
		c.models[key] = regional
	}
	return nil
}

// armModelMetadataValid applies Control's schema of a regional model: capabilities, when present,
// an object; deprecation, when present, an object whose inference date is a string; and the
// publisher a string.
func armModelMetadataValid(model map[string]json.RawMessage) bool {
	if raw, present := model["capabilities"]; present {
		if _, ok := armObject(raw); !ok {
			return false
		}
	}
	if raw, present := model["deprecation"]; present {
		deprecation, ok := armObject(raw)
		if !ok {
			return false
		}
		if _, ok := armOptionalString(deprecation, "inference", false); !ok {
			return false
		}
	}
	_, ok := armOptionalString(model, "publisher", false)
	return ok
}

// deploymentBindings makes the targets of the account's deployments. It also returns every
// deployment as gateways' checks report it, and the deployment names, which shadow Instant targets.
func (c *azureDiscoveryContext) deploymentBindings(values []json.RawMessage) ([]azureDiscoveredBinding, []billing.AzureDeployment, map[string]bool, error) {
	bindings := []azureDiscoveredBinding{}
	deployments := []billing.AzureDeployment{}
	seen := map[string]bool{}
	names := map[string]bool{}
	for _, value := range values {
		// Each deployment is decoded once, which keeps a listing at the bound on targets quick.
		object, objectOK := armObject(value)
		name, resourceID, err := azureAccountChildOf(object, objectOK, c.accountID, "deployments")
		if err != nil {
			return nil, nil, nil, err
		}
		// A page that repeats a deployment does not make a second target.
		if seen[resourceID] {
			continue
		}
		seen[resourceID] = true
		properties, propertiesOK := armObject(object["properties"])
		sku, skuOK := armObject(object["sku"])
		identity, model, modelOK := armModelIdentity(properties["model"])
		fact := armDeploymentFactOf(resourceID, properties, model, sku)
		deployments = append(deployments, fact)
		// Even an unsupported or changing named deployment shadows Instant access.
		names[strings.ToLower(name)] = true
		skuName, skuNameOK := armRequiredString(sku, "name")
		state, stateOK := armOptionalString(properties, "provisioningState", false)
		if !propertiesOK || !skuOK || !skuNameOK || !modelOK || !stateOK ||
			state != "" && strings.ToLower(trimJS(state)) != "succeeded" {
			continue
		}
		metadata := azureModelMetadataOf(model)
		if regional, ok := c.models[identity.key()]; ok {
			metadata = regional.azureModelMetadata
		}
		if metadata.deprecationAt != nil && !metadata.deprecationAt.After(c.discoveredAt) {
			continue
		}
		hosting := azureModelHosting(identity.format, metadata)
		if hosting == "" {
			continue
		}
		deploymentType, processing, storage, ok := c.placement(skuName, hosting)
		if !ok {
			continue
		}
		endpoint := c.foundry
		if strings.ToLower(trimJS(identity.format)) == "openai" || endpoint == "" {
			endpoint = c.openAI
			if endpoint == "" {
				endpoint = c.foundry
			}
		}
		if endpoint == "" {
			continue
		}
		if bindings, err = c.append(bindings, azureDiscoveredBinding{
			VersionUpgrade:       fact.VersionUpgrade,
			DeploymentName:       name,
			DeploymentResourceID: resourceID,
			DeploymentType:       deploymentType,
			Endpoint:             endpoint,
			Hosting:              hosting,
			ProcessingLocation:   processing,
			ModelDeprecationAt:   metadata.deprecationAt,
			ModelFormat:          trimJS(identity.format),
			ModelHostedOn:        metadata.hostedOn,
			ModelName:            trimJS(identity.name),
			ModelPublisher:       metadata.publisher,
			ModelVersion:         trimJS(identity.version),
			SkuName:              trimJS(skuName),
			StorageLocation:      storage,
			TokenScope:           azureDataScope,
		}); err != nil {
			return nil, nil, nil, err
		}
	}
	return bindings, deployments, names, nil
}

// instantBindings makes the Instant targets of the account's West US 3 projects: each model that
// Instant serves, that Azure hosts and that the account allows, under its versioned name, unless a
// deployment has that name.
func (c *azureDiscoveryContext) instantBindings(values []json.RawMessage, names map[string]bool, allowed map[string]bool) ([]azureDiscoveredBinding, error) {
	bindings := []azureDiscoveredBinding{}
	for _, value := range values {
		name, resourceID, err := azureAccountChild(value, c.accountID, "projects")
		if err != nil {
			return nil, err
		}
		object, _ := armObject(value)
		location, locationOK := armRequiredString(object, "location")
		properties, propertiesOK := armObject(object["properties"])
		state, stateOK := armOptionalString(properties, "provisioningState", false)
		if !locationOK || !propertiesOK || !stateOK || strings.ToLower(trimJS(location)) != azureInstantLocation ||
			state != "" && strings.ToLower(trimJS(state)) != "succeeded" || c.foundry == "" {
			continue
		}
		endpoint := c.foundry + "/api/projects/" + name
		for _, key := range c.modelOrder {
			model := c.models[key]
			if !model.instant || model.deprecationAt != nil && !model.deprecationAt.After(c.discoveredAt) ||
				allowed != nil && !allowed[key] {
				continue
			}
			if azureModelHosting(model.format, model.azureModelMetadata) != "azure" || !azureInstantVersion.MatchString(model.version) {
				continue
			}
			deploymentName := model.name + "-" + model.version
			if names[strings.ToLower(deploymentName)] {
				continue
			}
			if bindings, err = c.append(bindings, azureDiscoveredBinding{
				DeploymentName:       deploymentName,
				DeploymentResourceID: resourceID,
				DeploymentType:       "instant",
				Endpoint:             endpoint,
				Hosting:              "azure",
				ProcessingLocation:   "world",
				ModelDeprecationAt:   model.deprecationAt,
				ModelFormat:          model.format,
				ModelHostedOn:        model.hostedOn,
				ModelName:            model.name,
				ModelPublisher:       model.publisher,
				ModelVersion:         model.version,
				SkuName:              "Instant",
				StorageLocation:      c.storageLocation(),
				TokenScope:           azureDataScope,
			}); err != nil {
				return nil, err
			}
		}
	}
	return bindings, nil
}

// azureInstantAllowList reads the models that the account lets Instant serve, or nil when it sets
// no list, Azure's default access; an explicit empty list turns Instant off. Azure lists complete
// model identities, never patterns.
func azureInstantAllowList(ctx context.Context, reads *armReads, accountID string) (map[string]bool, error) {
	body, err := reads.data(ctx, armResource(accountID, armInstantAPIVersion), azureAccountDenied)
	if err != nil {
		return nil, err
	}
	invalid := azureDiscoveryFailed("Azure returned invalid Instant access controls")
	controls, ok := armObject(body)
	id, idOK := armRequiredString(controls, "id")
	properties, propertiesOK := armObject(controls["properties"])
	if !ok || !idOK || !propertiesOK || azureAccountResourceID(id) != accountID {
		return nil, invalid
	}
	raw, present := properties["instant"]
	if !present {
		return nil, nil
	}
	instant, ok := armObject(raw)
	if !ok {
		return nil, invalid
	}
	raw, present = instant["modelAllowList"]
	if !present {
		return nil, nil
	}
	var models []json.RawMessage
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '[' || json.Unmarshal(trimmed, &models) != nil ||
		len(models) > azureDiscoveryMaxBindings {
		return nil, invalid
	}
	allowed := make(map[string]bool, len(models))
	for _, value := range models {
		identity, _, ok := armModelIdentity(value)
		if !ok {
			return nil, invalid
		}
		allowed[identity.key()] = true
	}
	return allowed, nil
}

// azureHasModelRole reports whether the application's effective roles on the account, inherited
// ones included, grant model requests. Owner, Contributor and Reader grant no data actions. A shape
// that Control's schema does not expect is no evidence of a missing role.
func azureHasModelRole(ctx context.Context, reads *armReads, accountID string) (bool, error) {
	values, err := reads.pages(ctx, armResource(accountID+"/providers/Microsoft.Authorization/permissions", armPermissionsAPIVersion), azureAccountDenied)
	if err != nil {
		return false, err
	}
	return azureGrantsModelRequests(values), nil
}

// azureGrantsModelRequests reports whether a permission grants a Cognitive Services data action
// that its own notDataActions leave in place. Azure subtracts a role's notDataActions only from
// that role's dataActions, so each permission is read alone.
func azureGrantsModelRequests(values []json.RawMessage) bool {
	role := false
	for _, value := range values {
		permission, ok := armObject(value)
		if !ok {
			return true
		}
		granted, ok := armStrings(permission["dataActions"], false)
		if !ok {
			return true
		}
		excluded, ok := armStrings(permission["notDataActions"], true)
		if !ok {
			return true
		}
		for _, action := range granted {
			if model, ok := azureModelAction(action); ok && !slices.ContainsFunc(excluded, func(pattern string) bool { return azureActionCovers(pattern, model) }) {
				role = true
			}
		}
	}
	return role
}

// armStrings reads a JSON array of strings. An absent optional field is empty.
func armStrings(raw json.RawMessage, optional bool) ([]string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, optional
	}
	var items []json.RawMessage
	if raw[0] != '[' || json.Unmarshal(raw, &items) != nil {
		return nil, false
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		var value string
		if trimmed := bytes.TrimSpace(item); len(trimmed) == 0 || trimmed[0] != '"' || json.Unmarshal(trimmed, &value) != nil {
			return nil, false
		}
		values = append(values, value)
	}
	return values, true
}

// azureModelAction returns the part of a granted data action that model requests need.
func azureModelAction(action string) (string, bool) {
	action = strings.ToLower(action)
	if action == "*" {
		return "microsoft.cognitiveservices/*", true
	}
	return action, strings.HasPrefix(action, "microsoft.cognitiveservices/")
}

// azureActionCovers reports whether pattern matches every operation that the lowercase action
// matches. Only a trailing wildcard is compared; any other pattern covers only an equal action,
// so it never hides a granted role.
func azureActionCovers(pattern, action string) bool {
	pattern = strings.ToLower(pattern)
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok && !strings.Contains(prefix, "*") {
		return strings.HasPrefix(action, prefix)
	}
	return pattern == action
}
