//go:build wasip1

// Package main exposes the native policy compiler as a synchronous WASI reactor.
package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"maps"
	"runtime"
	"runtime/debug"
	"slices"
	_ "time/tzdata"
	"unsafe"

	"github.com/maximhq/bifrost/transports/stogas/location"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// Each call carries one bounded source or the old source for an edit. Allow
// whitespace and JSON framing without allocating a whole source collection.
const maximumInputBytes = 2*policy.MaxStoredSourceBytes + 16<<10

var input, output []byte
var inspector *policy.Inspector

// received counts the bytes of the sources that a result describes. The result holds their
// settings twice at most, compiled and as the combined view shows them.
var received int

// placesJSON is the locations of the catalog that the gateway embeds as its fallback, written
// beside this file whenever that fallback is synced with the catalog.
//
//go:embed places.json
var placesJSON []byte

// companiesJSON is the companies of the same catalog, written with the places.
//
//go:embed companies.json
var companiesJSON []byte

func init() {
	// Leave room in a 128-MiB host for its JavaScript heap and the JSON bridge.
	// This is GC pacing, not an input-validation or hard memory boundary.
	debug.SetMemoryLimit(48 << 20)
	places, err := location.Decode(placesJSON)
	if err != nil {
		panic(err)
	}
	var companies map[string]json.RawMessage
	if err := json.Unmarshal(companiesJSON, &companies); err != nil {
		panic(err)
	}
	// A saved policy names only places and companies that the catalog lists.
	policy.CheckPlaces(places)
	policy.CheckCompanies(slices.Collect(maps.Keys(companies)))
}

//go:wasmexport allocate
func allocate(size uint32) uint32 {
	input, output = nil, nil
	if size == 0 || size > maximumInputBytes {
		return 0
	}
	input = make([]byte, size)
	return uint32(uintptr(unsafe.Pointer(&input[0])))
}

//go:wasmexport inspect
func inspect() uint64 {
	result, err := inspectRequest(input)
	input = nil
	if result != nil && result.Effective != nil {
		// The binding already owns the exact input envelopes. Return their
		// ordered references; copying their blobs back would double peak
		// memory without adding any validation or policy information.
		if opaque, ok := result.Effective["uncheckedPlugins"].([]map[string]any); ok {
			for _, item := range opaque {
				delete(item, "encrypted")
			}
		}
	}
	var response any = result
	if err != nil {
		status := 400
		if errors.Is(err, policy.ErrPolicyEditForbidden) {
			status = 403
		}
		response = map[string]any{"error": map[string]any{"message": err.Error(), "status": status}}
	}
	// A chain's result can take megabytes, and this memory never shrinks. So the encoder writes
	// into one buffer of about the result's size instead of growing its own by doubling.
	var encoded bytes.Buffer
	if result != nil {
		encoded.Grow(2 * received)
	}
	if jsonv2.MarshalWrite(&encoded, response, json.DefaultOptionsV1()) != nil {
		panic("cannot encode policy inspection")
	}
	output = encoded.Bytes()
	return uint64(uintptr(unsafe.Pointer(&output[0])))<<32 | uint64(len(output))
}

//go:wasmexport release
func release() {
	input, output = nil, nil
	inspector = nil
	// A reactor is suspended between host calls, so collect request-owned
	// objects here before the host starts its next inspection.
	runtime.GC()
}

func inspectRequest(raw []byte) (*policy.Inspection, error) {
	var request struct {
		Operation string                   `json:"operation"`
		Source    json.RawMessage          `json:"source"`
		Item      *policy.InspectionSource `json:"item"`
		Edit      *policy.InspectionEdit   `json:"edit"`
	}
	if jsonv2.Unmarshal(raw, &request, jsonv2.RejectUnknownMembers(true)) != nil {
		return nil, errors.New("invalid policy inspection request")
	}
	switch request.Operation {
	case "source":
		if request.Item != nil || request.Edit != nil {
			return nil, errors.New("invalid source inspection request")
		}
		received = len(request.Source)
		return policy.InspectSource(request.Source)
	case "begin":
		if request.Source != nil || request.Item != nil {
			return nil, errors.New("invalid combined inspection request")
		}
		inspector, received = policy.NewInspector(request.Edit, true), 0
		return nil, nil
	case "append":
		if inspector == nil || request.Item == nil || request.Source != nil || request.Edit != nil {
			return nil, errors.New("invalid inspection source request")
		}
		received += len(request.Item.Config)
		return nil, inspector.Add(*request.Item)
	case "finish":
		if inspector == nil || request.Item != nil || request.Source != nil || request.Edit != nil {
			return nil, errors.New("invalid inspection completion request")
		}
		result, err := inspector.Finish()
		inspector = nil
		return result, err
	}
	return nil, errors.New("invalid policy inspection operation")
}

func main() {}
