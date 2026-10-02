//go:build wasip1

// Package main exposes the native policy compiler as a synchronous WASI reactor.
package main

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"runtime"
	"runtime/debug"
	_ "time/tzdata"
	"unsafe"

	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// Each call carries one bounded source or the old source for an edit. Allow
// whitespace and JSON framing without allocating a whole source collection.
const maximumInputBytes = 2*policy.MaxStoredSourceBytes + 16<<10

var input, output []byte
var inspector *policy.Inspector

func init() {
	// Leave room in a 128-MiB host for its JavaScript heap and the JSON bridge.
	// This is GC pacing, not an input-validation or hard memory boundary.
	debug.SetMemoryLimit(48 << 20)
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
	output, err = json.Marshal(response)
	if err != nil {
		panic("cannot encode policy inspection")
	}
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
		return policy.InspectSource(request.Source)
	case "begin":
		if request.Source != nil || request.Item != nil {
			return nil, errors.New("invalid combined inspection request")
		}
		inspector = policy.NewInspector(request.Edit, true)
		return nil, nil
	case "append":
		if inspector == nil || request.Item == nil || request.Source != nil || request.Edit != nil {
			return nil, errors.New("invalid inspection source request")
		}
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
