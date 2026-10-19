package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/confidential/clock"
)

const (
	clockConfigPath = "/etc/ntpd-rs/ntp.toml"
	clockDaemonPath = "/stogas/ntp-daemon"
	envFallbackPath = "/stogas/env"
	envFWCfgPath    = "/sys/firmware/qemu_fw_cfg/by_name/opt/stogas/env/raw"
	gatewayPath     = "/stogas/gateway.init"
)

type initReasonCode string

const (
	initClockDaemonFailed        initReasonCode = "clock_daemon_failed"
	initClockRaised              initReasonCode = "clock_raised_to_release_time"
	initClockSetFailed           initReasonCode = "clock_set_failed"
	initConfigurationOpenFailed  initReasonCode = "configuration_open_failed"
	initConfigurationReadFailed  initReasonCode = "configuration_read_failed"
	initExecFailed               initReasonCode = "gateway_exec_failed"
	initInvalidConfiguration     initReasonCode = "invalid_configuration_line"
	initMountDevFailed           initReasonCode = "mount_dev_failed"
	initMountFailed              initReasonCode = "mount_failed"
	initMountProcFailed          initReasonCode = "mount_proc_failed"
	initMountSysFailed           initReasonCode = "mount_sys_failed"
	initUnsupportedConfigKey     initReasonCode = "unsupported_configuration_key"
	initUpstreamConnectionFailed initReasonCode = "upstream_connection_failed"
	initUpstreamConnectionOK     initReasonCode = "upstream_connection_succeeded"
	initUpstreamURLInvalid       initReasonCode = "upstream_url_invalid"
)

var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var forwardConfigKeys = map[string]struct{}{
	"STOGAS_INSTANCE_ID":                     {},
	"STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID":     {},
	"STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET": {},
	"STOGAS_ENVIRONMENT":                     {},
}

func main() {
	if os.Getpid() != 1 {
		writeInitEvent(os.Stderr, "guest_init_failed", "error", initExecFailed)
		os.Exit(1)
	}
	// The kernel's ACPI power button driver sends SIGTERM when the host stops
	// the guest.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(shutdown)
	mount(os.Stderr, "proc", "/proc", "proc")
	mount(os.Stderr, "sysfs", "/sys", "sysfs")
	mount(os.Stderr, "devtmpfs", "/dev", "devtmpfs")

	loadEnv(os.Stderr, envFWCfgPath, forwardConfigKeys)
	if localEnvironment(os.Getenv("STOGAS_ENVIRONMENT")) {
		loadEnv(os.Stderr, envFallbackPath, nil)
	}
	probeURL(os.Stderr, "OPENAI_BASE_URL")

	args := []string{
		gatewayPath,
		"-host", envDefault("STOGAS_GATEWAY_HOST", "0.0.0.0"),
		"-port", envDefault("STOGAS_GATEWAY_PORT", "5185"),
		"-log-style", "json",
		"-log-level", "info",
	}
	daemon := exec.Command(clockDaemonPath, "--config", clockConfigPath)
	daemon.Stdout, daemon.Stderr = os.Stdout, os.Stderr
	command := exec.Command(args[0], args[1:]...)
	// The host writes and reads this console, so the gateway reads no input
	// from it, and a gateway crash must not print the registers and stack
	// contents that the Go runtime prints by default.
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	command.Env = append(os.Environ(), "GOTRACEBACK=none")
	if err := raiseClock(os.Stderr, time.Now(), releaseTime, setClock); err != nil {
		writeInitEvent(os.Stderr, "guest_init_failed", "error", initClockSetFailed)
	} else if err := runGuest(daemon, command, shutdown, clock.Synchronized); errors.Is(err, errClockDaemon) {
		writeInitEvent(os.Stderr, "guest_init_failed", "error", initClockDaemonFailed)
	} else if err != nil {
		writeInitEvent(os.Stderr, "guest_init_failed", "error", initExecFailed)
	}
	// Any gateway exit ends this ephemeral guest. The host's desired service
	// state decides whether to start new capacity; this init never restarts keys.
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
	os.Exit(127)
}

func mount(output io.Writer, source, target, fstype string) {
	if err := os.MkdirAll(target, 0o755); err != nil {
		writeInitEvent(output, "guest_init_warning", "warn", mountFailureReason(target))
		return
	}
	if err := syscall.Mount(source, target, fstype, 0, ""); err != nil && err != syscall.EBUSY {
		writeInitEvent(output, "guest_init_warning", "warn", mountFailureReason(target))
	}
}

func loadEnv(output io.Writer, path string, allowedKeys map[string]struct{}) {
	file, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			writeInitEvent(output, "guest_init_warning", "warn", initConfigurationOpenFailed)
		}
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	invalidLineReported := false
	unsupportedKeyReported := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || !envKeyPattern.MatchString(key) {
			if !invalidLineReported {
				writeInitEvent(output, "guest_init_warning", "warn", initInvalidConfiguration)
				invalidLineReported = true
			}
			continue
		}
		if allowedKeys != nil {
			if _, allowed := allowedKeys[key]; !allowed {
				if !unsupportedKeyReported {
					writeInitEvent(output, "guest_init_warning", "warn", initUnsupportedConfigKey)
					unsupportedKeyReported = true
				}
				continue
			}
		}
		if err := os.Setenv(key, strings.TrimSpace(value)); err != nil && !invalidLineReported {
			writeInitEvent(output, "guest_init_warning", "warn", initInvalidConfiguration)
			invalidLineReported = true
		}
	}
	if err := scanner.Err(); err != nil {
		writeInitEvent(output, "guest_init_warning", "warn", initConfigurationReadFailed)
	}
}

func probeURL(output io.Writer, name string) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return
	}
	address, err := probeAddress(raw)
	if err != nil {
		writeInitEvent(output, "guest_init_warning", "warn", initUpstreamURLInvalid)
		return
	}
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		writeInitEvent(output, "guest_init_warning", "warn", initUpstreamConnectionFailed)
		return
	}
	_ = conn.Close()
	writeInitEvent(output, "guest_init_probe", "info", initUpstreamConnectionOK)
}

func probeAddress(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return "", fmt.Errorf("invalid upstream URL")
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(parsed.Hostname(), port), nil
}

func mountFailureReason(target string) initReasonCode {
	switch target {
	case "/proc":
		return initMountProcFailed
	case "/sys":
		return initMountSysFailed
	case "/dev":
		return initMountDevFailed
	default:
		return initMountFailed
	}
}

func writeInitEvent(output io.Writer, event string, severity string, reasonCode initReasonCode) {
	payload, err := json.Marshal(struct {
		ErrorType  string `json:"errorType,omitempty"`
		Event      string `json:"event"`
		ReasonCode string `json:"reasonCode"`
		Severity   string `json:"severity"`
	}{
		ErrorType:  initErrorType(severity),
		Event:      event,
		ReasonCode: string(reasonCode),
		Severity:   severity,
	})
	if err == nil {
		_, _ = fmt.Fprintln(output, string(payload))
	}
}

func initErrorType(severity string) string {
	if severity == "info" {
		return ""
	}
	return "Error"
}

func envDefault(name string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func localEnvironment(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "local")
}
