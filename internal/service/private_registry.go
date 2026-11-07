package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/sandbox"
	"github.com/rheic/sandboxes-gateway/registryauth"

	"github.com/rheic/sandboxes-daemon/internal/registrycredentials"
	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
)

const (
	privateRegistryProxyService = "registry-private"
	privateRegistryGuestPort    = uint16(43135)
)

func privateRegistrySettingKey(id string) string { return "sandbox.registry-private." + id }

// SetPrivateRegistry configures the single allowlisted private registry that
// the guest registry proxy may reach. Empty host disables the feature.
func (s *Service) SetPrivateRegistry(host, service string, realms, redirects []string, caPEM []byte) error {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		if service != "" || len(realms) != 0 || len(redirects) != 0 {
			return errors.New("private registry host is required")
		}
		return nil
	}
	if !validRegistryHost(host) {
		return fmt.Errorf("%w: private registry host is invalid", core.ErrConflict)
	}
	if service == "" || strings.ContainsAny(service, " \t\r\n") {
		return fmt.Errorf("%w: private registry service is required", core.ErrConflict)
	}
	parsed, err := parsePrivateRealms(realms)
	if err != nil {
		return err
	}
	cleanRedirects, err := parsePrivateRedirects(redirects)
	if err != nil {
		return err
	}
	var roots *x509.CertPool
	if len(caPEM) != 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("%w: private registry CA bundle is invalid", core.ErrConflict)
		}
	}
	s.privateRegistryHost = host
	s.privateRegistrySvc = service
	s.privateRegistryRealms = parsed
	s.privateRegistryRedirects = cleanRedirects
	s.privateRegistryRoots = roots
	return nil
}

func parsePrivateRealms(realms []string) ([]registryauth.Realm, error) {
	parsed := make([]registryauth.Realm, 0, len(realms))
	for _, raw := range realms {
		realmHost, path, found := strings.Cut(raw, "/")
		realmHost = strings.ToLower(strings.TrimSpace(realmHost))
		if !found || !validRegistryHost(realmHost) || path == "" || strings.ContainsAny(path, "?#\\") || strings.Contains(path, "..") {
			return nil, fmt.Errorf("%w: private registry realm is invalid", core.ErrConflict)
		}
		parsed = append(parsed, registryauth.Realm{Host: realmHost, Path: "/" + strings.TrimPrefix(path, "/")})
	}
	if len(parsed) == 0 {
		return nil, fmt.Errorf("%w: private registry realm is required", core.ErrConflict)
	}
	return parsed, nil
}

func parsePrivateRedirects(redirects []string) ([]string, error) {
	clean := make([]string, 0, len(redirects))
	for _, redirect := range redirects {
		redirect = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(redirect), "."))
		if !validRegistryHost(redirect) {
			return nil, fmt.Errorf("%w: private registry redirect host is invalid", core.ErrConflict)
		}
		clean = append(clean, redirect)
	}
	return clean, nil
}

func validRegistryHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "*/@?#\\ \t\r\n") || strings.Contains(host, "://") || strings.HasSuffix(host, ".") {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !validRegistryLabel(label) {
			return false
		}
	}
	return true
}

func validRegistryLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, char := range label {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
			continue
		}
		return false
	}
	return true
}

func (s *Service) privateRegistryScopeFor(ctx context.Context, id string) (registrycredentials.Scope, error) {
	value, err := s.store.GetSetting(ctx, privateRegistrySettingKey(id))
	if errors.Is(err, core.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("load sandbox private registry scope: %w", err)
	}
	scope := registrycredentials.Scope(value)
	if scope != registrycredentials.ScopeSandbox && scope != registrycredentials.ScopeAllSandboxes {
		return "", errors.New("sandbox private registry scope is invalid")
	}
	return scope, nil
}

func (s *Service) privateRegistryConfigured() bool {
	return s.privateRegistryHost != "" && s.registryCredentials != nil
}

func (s *Service) availablePrivateRegistryScope(ctx context.Context, sandboxName string, allowAll bool) (registrycredentials.Scope, error) {
	if !s.privateRegistryConfigured() {
		return "", nil
	}
	if credential, err := s.registryCredentials.Load(ctx, s.privateRegistryHost, registrycredentials.ScopeSandbox, sandboxName); err == nil {
		clear(credential.Password)
		return registrycredentials.ScopeSandbox, nil
	} else if !errors.Is(err, registrycredentials.ErrNotFound) {
		return "", err
	}
	if !allowAll {
		return "", nil
	}
	if credential, err := s.registryCredentials.Load(ctx, s.privateRegistryHost, registrycredentials.ScopeAllSandboxes, ""); err == nil {
		clear(credential.Password)
		return registrycredentials.ScopeAllSandboxes, nil
	} else if !errors.Is(err, registrycredentials.ErrNotFound) {
		return "", err
	}
	return "", nil
}

type privateRegistryTransportFactory struct {
	service   *Service
	sandboxID string
	host      string
	realms    []registryauth.Realm
	redirects []string
	roots     *x509.CertPool
}

func (f privateRegistryTransportFactory) Registry(ctx context.Context, authority string) (http.RoundTripper, error) {
	if !strings.EqualFold(authority, f.host) {
		return nil, errors.New("untrusted private registry authority")
	}
	prefixes, err := f.prefixes(ctx, authority)
	if err != nil {
		return nil, err
	}
	return registrycredentials.NewForwardRegistryTransport(authority, prefixes, f.roots)
}

func (f privateRegistryTransportFactory) Token(ctx context.Context, realm registryauth.Realm) (http.RoundTripper, error) {
	trusted := false
	for _, candidate := range f.realms {
		if strings.EqualFold(candidate.Host, realm.Host) && candidate.Path == realm.Path {
			trusted = true
		}
	}
	if !trusted {
		return nil, errors.New("untrusted private registry token realm")
	}
	prefixes, err := f.prefixes(ctx, realm.Host)
	if err != nil {
		return nil, err
	}
	return registryauth.NewTokenTransport(realm, prefixes, f.roots)
}

func (f privateRegistryTransportFactory) Redirect(ctx context.Context, authority string) (http.RoundTripper, error) {
	trusted := false
	for _, candidate := range f.redirects {
		if strings.EqualFold(candidate, authority) {
			trusted = true
		}
	}
	if !trusted {
		return nil, errors.New("untrusted private registry redirect authority")
	}
	prefixes, err := f.prefixes(ctx, authority)
	if err != nil {
		return nil, err
	}
	addresses := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		addresses = append(addresses, prefix.Addr().String())
	}
	var next atomic.Uint64
	return &http.Transport{
		Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: f.roots, ServerName: authority},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != net.JoinHostPort(authority, "443") {
				return nil, errors.New("redirect transport rejected unexpected destination")
			}
			start := int(next.Add(1) % uint64(len(addresses))) //nolint:gosec // bounded by len(addresses).
			var failures []error
			for offset := range addresses {
				ip := addresses[(start+offset)%len(addresses)]
				conn, dialErr := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip, "443"))
				if dialErr == nil {
					return conn, nil
				}
				failures = append(failures, dialErr)
			}
			return nil, errors.Join(failures...)
		},
	}, nil
}

func (f privateRegistryTransportFactory) prefixes(ctx context.Context, host string) ([]netip.Prefix, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("private registry DNS lookup failed")
	}
	prefixes := make([]netip.Prefix, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() || address.IsMulticast() {
			// A hostname may resolve to loopback in addition to reachable
			// addresses; skip the unusable entry and keep the verified set.
			continue
		}
		decision, err := f.service.checkResolvedEgress(ctx, f.sandboxID, host, address)
		if err != nil {
			return nil, err
		}
		if !decision.Allowed {
			continue
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
	}
	if len(prefixes) == 0 {
		return nil, errors.New("sandbox policy denied private registry")
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].Addr().Less(prefixes[j].Addr()) })
	return prefixes, nil
}

func (s *Service) buildPrivateRegistryProxy(ctx context.Context, sb sandbox.Sandbox, scope registrycredentials.Scope) (secretproxy.RouteConfig, string, error) {
	if !s.privateRegistryConfigured() {
		return secretproxy.RouteConfig{}, "", fmt.Errorf("%w: private registry is not configured (%q)", core.ErrConflict, s.privateRegistryHost)
	}
	if scope != registrycredentials.ScopeSandbox && scope != registrycredentials.ScopeAllSandboxes {
		return secretproxy.RouteConfig{}, "", fmt.Errorf("%w: private registry scope %q is invalid", core.ErrConflict, scope)
	}
	ca, err := s.registryCredentials.ProxyCA(ctx)
	if err != nil {
		return secretproxy.RouteConfig{}, "", fmt.Errorf("load private registry proxy CA: %w", err)
	}
	hosts := []string{s.privateRegistryHost}
	for _, realm := range s.privateRegistryRealms {
		hosts = append(hosts, realm.Host)
	}
	hosts = append(hosts, s.privateRegistryRedirects...)
	ca.AllowHosts(hosts...)
	proxy, err := registrycredentials.NewPullProxy(s.registryCredentials, registrycredentials.PullProxyConfig{
		Registry: s.privateRegistryHost, Authority: s.privateRegistryHost, SandboxName: sb.Name,
		CredentialScope: scope, Service: s.privateRegistrySvc,
		Realms: s.privateRegistryRealms, RedirectAuthorities: s.privateRegistryRedirects,
		TransportFactory: privateRegistryTransportFactory{
			service: s, sandboxID: sb.ID, host: s.privateRegistryHost,
			realms: s.privateRegistryRealms, redirects: s.privateRegistryRedirects, roots: s.privateRegistryRoots,
		},
		Limiter: s.registryPullLimiter, MaxBytes: 16 << 30, TLSAuthority: ca,
	})
	if err != nil {
		return secretproxy.RouteConfig{}, "", fmt.Errorf("configure private registry broker: %w", err)
	}
	token, err := newProxyToken()
	if err != nil {
		return secretproxy.RouteConfig{}, "", err
	}
	return secretproxy.RouteConfig{
		Service: secretproxy.Service{Upstream: "https://" + s.privateRegistryHost, CredentialScope: string(scope)},
		Handler: proxy, Token: token, CACert: ca.Certificate(), MaxRequestBody: 16 << 30,
	}, fmt.Sprintf("%s=%s:%d", privateRegistryProxyService, s.privateRegistryHost, privateRegistryGuestPort), nil
}
