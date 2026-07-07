package main

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	envFallbackPath = "/stogas/env"
	envFWCfgPath    = "/sys/firmware/qemu_fw_cfg/by_name/opt/stogas/env/raw"
	gatewayPath     = "/stogas/gateway.init"
)

var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var forwardConfigKeys = map[string]struct{}{
	"STOGAS_CLOUDFLARE_ACCESS_CLIENT_ID":     {},
	"STOGAS_CLOUDFLARE_ACCESS_CLIENT_SECRET": {},
	"STOGAS_ENVIRONMENT":                     {},
}

func main() {
	mount("proc", "/proc", "proc")
	mount("sysfs", "/sys", "sysfs")
	mount("devtmpfs", "/dev", "devtmpfs")

	loadEnv(envFWCfgPath, forwardConfigKeys)
	if localEnvironment(os.Getenv("STOGAS_ENVIRONMENT")) {
		loadEnv(envFallbackPath, nil)
	}
	probeURL("OPENAI_BASE_URL")

	args := []string{
		gatewayPath,
		"-host", envDefault("STOGAS_GATEWAY_HOST", "0.0.0.0"),
		"-port", envDefault("STOGAS_GATEWAY_PORT", "5185"),
		"-log-style", "json",
		"-log-level", "info",
	}
	if err := syscall.Exec(args[0], args, os.Environ()); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "stogas-init: exec %s failed: %v\n", gatewayPath, err)
		_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
		os.Exit(127)
	}
}

func mount(source, target, fstype string) {
	_ = os.MkdirAll(target, 0o755)
	if err := syscall.Mount(source, target, fstype, 0, ""); err != nil && err != syscall.EBUSY {
		_, _ = fmt.Fprintf(os.Stderr, "stogas-init: mount %s failed: %v\n", target, err)
	}
}

func loadEnv(path string, allowedKeys map[string]struct{}) {
	file, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			_, _ = fmt.Fprintf(os.Stderr, "stogas-init: open %s failed: %v\n", path, err)
		}
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || !envKeyPattern.MatchString(key) {
			_, _ = fmt.Fprintf(os.Stderr, "stogas-init: ignored invalid env line in %s\n", path)
			continue
		}
		if allowedKeys != nil {
			if _, allowed := allowedKeys[key]; !allowed {
				_, _ = fmt.Fprintf(os.Stderr, "stogas-init: ignored unsupported forward config key %s\n", key)
				continue
			}
		}
		_ = os.Setenv(key, strings.TrimSpace(value))
	}
	if err := scanner.Err(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "stogas-init: read %s failed: %v\n", path, err)
	}
}

func probeURL(name string) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "stogas-init: %s parse failed: %v\n", name, err)
		return
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	address := net.JoinHostPort(parsed.Hostname(), port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "stogas-init: %s tcp probe %s failed: %v\n", name, address, err)
		return
	}
	_ = conn.Close()
	_, _ = fmt.Fprintf(os.Stderr, "stogas-init: %s tcp probe %s ok\n", name, address)
}

func envDefault(name string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func localEnvironment(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "local", "test", "testing":
		return true
	default:
		return false
	}
}
