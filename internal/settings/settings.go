// Package settings loads the host-side Rheic settings file.
package settings

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Values are the supported user overrides. Zero means "not set".
type Values struct {
	DNSUpstream           string
	MCPRemoteAllowedHosts []string
	DefaultPolicyProfile  string
	DefaultCPUs           uint32
	DefaultMemoryMiB      uint32
	DockerVolumeSize      string
	// RegistryPrivate configures one explicitly allowlisted private registry
	// reached through the guest registry proxy. Empty disables the feature.
	RegistryPrivateHost      string
	RegistryPrivateService   string
	RegistryPrivateRealms    []string
	RegistryPrivateRedirects []string
	// RegistryPrivateCA is an optional host-side PEM bundle for a private CA.
	RegistryPrivateCA string
}

// DefaultPath returns ~/.config/rheic/settings.toml, honoring XDG_CONFIG_HOME.
func DefaultPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "rheic", "settings.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "rheic", "settings.toml")
}

// Load reads the optional settings file. A missing file is not an error.
func Load(path string) (Values, error) {
	var values Values
	if path == "" {
		return values, nil
	}
	file, err := os.Open(path) // #nosec G304 -- path is the user settings location
	if errors.Is(err, os.ErrNotExist) {
		return values, nil
	}
	if err != nil {
		return values, fmt.Errorf("open settings: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return values, fmt.Errorf("stat settings: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return values, errors.New("settings file must be a regular file not writable by group or others")
	}
	if err := parse(file, &values); err != nil {
		return values, err
	}
	if err := validateValues(values); err != nil {
		return values, err
	}
	return values, nil
}

func validateValues(values Values) error {
	if values.DNSUpstream != "" {
		host, port, err := net.SplitHostPort(values.DNSUpstream)
		if err != nil || host == "" || port == "" {
			return errors.New("settings dns_upstream must be HOST:PORT")
		}
		if parsed, err := strconv.ParseUint(port, 10, 16); err != nil || parsed == 0 {
			return errors.New("settings dns_upstream port must be 1..65535")
		}
	}
	switch values.DefaultPolicyProfile {
	case "", "deny-all", "balanced", "sbx-compat", "allow-all":
	default:
		return errors.New("settings default_policy_profile is invalid")
	}
	if values.DefaultCPUs > 64 {
		return errors.New("settings default_cpus must be at most 64")
	}
	if values.DefaultMemoryMiB > 32768 {
		return errors.New("settings default_memory_mib must be at most 32768")
	}
	return validateRegistryPrivate(values)
}

func validateRegistryPrivate(values Values) error {
	if values.RegistryPrivateHost == "" {
		if values.RegistryPrivateService != "" || len(values.RegistryPrivateRealms) != 0 || len(values.RegistryPrivateRedirects) != 0 {
			return errors.New("settings registry_private_* require registry_private_host")
		}
		return nil
	}
	if !validDNSHost(values.RegistryPrivateHost) {
		return errors.New("settings registry_private_host must be an exact DNS hostname")
	}
	if values.RegistryPrivateService == "" || len(values.RegistryPrivateService) > 253 || strings.ContainsAny(values.RegistryPrivateService, " \t\r\n") {
		return errors.New("settings registry_private_service is required and must be a token")
	}
	if len(values.RegistryPrivateRealms) == 0 {
		return errors.New("settings registry_private_realms is required")
	}
	return nil
}

func parseRegistryRealms(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	seen := make(map[string]struct{})
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		host, path, found := strings.Cut(part, "/")
		host = strings.ToLower(strings.TrimSpace(host))
		if !found || !validDNSHost(host) || path == "" || strings.ContainsAny(path, "?#\\") || strings.Contains(path, "..") {
			return nil, errors.New("registry_private_realms must be a comma-separated list of HOST/PATH")
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		entry := host + path
		if _, exists := seen[entry]; exists {
			return nil, errors.New("registry_private_realms contains a duplicate entry")
		}
		seen[entry] = struct{}{}
		out = append(out, entry)
	}
	return out, nil
}

//nolint:gocyclo,cyclop // flat settings key dispatch; helpers own the per-key validation.
func parse(r io.Reader, values *Values) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, raw, found := strings.Cut(line, "=")
		if !found {
			return fmt.Errorf("settings line %d: expected key = value", lineNumber)
		}
		key = strings.TrimSpace(key)
		raw = strings.TrimSpace(raw)
		value, err := parseValue(raw)
		if err != nil {
			return fmt.Errorf("settings line %d: %w", lineNumber, err)
		}
		switch key {
		case "dns_upstream":
			values.DNSUpstream = value
		case "mcp_remote_allowed_hosts", "mcp.remote.allowedHosts":
			values.MCPRemoteAllowedHosts, err = parseHostList(value)
			if err != nil {
				return fmt.Errorf("settings line %d: %w", lineNumber, err)
			}
		case "default_policy_profile":
			values.DefaultPolicyProfile = value
		case "default_cpus", "default_memory_mib":
			if err := parseDefaultResource(values, key, value); err != nil {
				return fmt.Errorf("settings line %d: %w", lineNumber, err)
			}
		case "docker_volume_size":
			values.DockerVolumeSize = value
		case "registry_private_host", "registry_private_service", "registry_private_realms", "registry_private_redirects", "registry_private_ca":
			if err := parseRegistryPrivateSetting(values, key, value); err != nil {
				return fmt.Errorf("settings line %d: %w", lineNumber, err)
			}
		default:
			return fmt.Errorf("settings line %d: unknown key %q", lineNumber, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	return nil
}

func parseRegistryPrivateSetting(values *Values, key, value string) error {
	switch key {
	case "registry_private_host":
		values.RegistryPrivateHost = strings.ToLower(strings.TrimSpace(value))
	case "registry_private_service":
		values.RegistryPrivateService = strings.TrimSpace(value)
	case "registry_private_realms":
		realms, err := parseRegistryRealms(value)
		if err != nil {
			return err
		}
		values.RegistryPrivateRealms = realms
	case "registry_private_redirects":
		redirects, err := parseHostList(value)
		if err != nil {
			return err
		}
		values.RegistryPrivateRedirects = redirects
	case "registry_private_ca":
		values.RegistryPrivateCA = strings.TrimSpace(value)
	}
	return nil
}

func parseDefaultResource(values *Values, key, value string) error {
	parsed, err := parseUint(key, value, 32)
	if err != nil {
		return err
	}
	if key == "default_cpus" {
		if parsed > 64 {
			return errors.New("default_cpus must be at most 64")
		}
		values.DefaultCPUs = uint32(parsed)
		return nil
	}
	values.DefaultMemoryMiB = uint32(parsed) //nolint:gosec // ParseUint uses 32 bits and validateValues applies the 32768 MiB limit.
	return nil
}

func parseHostList(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	seen := make(map[string]struct{})
	hosts := strings.Split(value, ",")
	for i := range hosts {
		host := strings.ToLower(strings.TrimSpace(hosts[i]))
		if !validDNSHost(host) {
			return nil, errors.New("mcp_remote_allowed_hosts must be a comma-separated list of exact DNS hostnames")
		}
		if _, exists := seen[host]; exists {
			return nil, errors.New("mcp_remote_allowed_hosts contains a duplicate hostname")
		}
		seen[host] = struct{}{}
		hosts[i] = host
	}
	return hosts, nil
}

func validDNSHost(host string) bool {
	if host == "" || len(host) > 253 || strings.Contains(host, "*") || strings.HasSuffix(host, ".") {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

func validDNSLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, char := range label {
		valid := char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-'
		if !valid {
			return false
		}
	}
	return true
}

func parseValue(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("empty value")
	}
	if raw[0] != '"' {
		return raw, nil
	}
	value, err := strconv.Unquote(raw)
	if err != nil {
		return "", fmt.Errorf("invalid quoted string: %w", err)
	}
	return value, nil
}

func parseUint(key, value string, bits int) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("%s must be a non-negative integer", key)
	}
	return parsed, nil
}
