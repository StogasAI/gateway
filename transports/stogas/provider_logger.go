package stogas

import (
	"os"
	"path"
	"runtime"
	"strconv"

	"github.com/maximhq/bifrost/core/schemas"
)

// Provider libraries can log response content in both format strings and
// arguments. Never format either, even when an operator enables debug logging.
type providerLibraryLogger struct {
	emit func(operationalLogEvent)
}

var _ schemas.Logger = providerLibraryLogger{}

func (providerLibraryLogger) Debug(string, ...any) {}
func (providerLibraryLogger) Info(string, ...any)  {}
func (logger providerLibraryLogger) Warn(string, ...any) {
	logger.emit(operationalLogEvent{Event: "provider_runtime_warning", Severity: "warn", Source: providerLogSource()})
}
func (logger providerLibraryLogger) Error(string, ...any) {
	logger.emit(operationalLogEvent{Event: "provider_runtime_error", Severity: "error", Source: providerLogSource()})
}
func (logger providerLibraryLogger) Fatal(string, ...any) {
	logger.emit(operationalLogEvent{Event: "provider_runtime_fatal", Severity: "error", Source: providerLogSource()})
	os.Exit(1)
}
func (providerLibraryLogger) SetLevel(schemas.LogLevel)              {}
func (providerLibraryLogger) SetOutputType(schemas.LoggerOutputType) {}
func (providerLibraryLogger) LogHTTPRequest(schemas.LogLevel, string) schemas.LogEventBuilder {
	return schemas.NoopLogEvent
}

// Like a conventional short caller field, retain only the source directory,
// file, and line. Compiler-owned locations distinguish faults without reading
// message text, request data, or the machine's absolute build path.
func providerLogSource() string {
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		return ""
	}
	return path.Base(path.Dir(file)) + "/" + path.Base(file) + ":" + strconv.Itoa(line)
}
