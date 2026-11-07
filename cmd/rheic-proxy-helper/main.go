// Command rheic-proxy-helper runs inside a sandbox and forwards HTTP requests
// over the per-VM vsock channel to the host broker. The broker owns the real
// service credential; the helper only carries the per-VM token.
//go:build linux

// rheic-proxy-helper runs inside the Linux guest and uses AF_VSOCK and Linux
// device/syscall interfaces. It is deliberately not a Windows host executable.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tokenHeader   = "X-Rheic-Proxy-Token"   //nolint:gosec // HTTP header name, not a credential.
	serviceHeader = "X-Rheic-Proxy-Service" //nolint:gosec // route metadata, not a credential.
	afVsock       = 40
)

type proxyRoute struct {
	service string
	host    string
	port    uint16
}

type routeFlags []string

func (r *routeFlags) String() string { return strings.Join(*r, ",") }

func (r *routeFlags) Set(value string) error {
	*r = append(*r, value)
	return nil
}

type sockaddrVM struct {
	Family    uint16
	Reserved1 uint16
	Port      uint32
	CID       uint32
	Flags     uint8
	Zero      [3]byte
}

type vsockAddr struct {
	cid  uint32
	port uint32
}

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string  { return fmt.Sprintf("%d:%d", a.cid, a.port) }

type vsockConn struct {
	file   *os.File
	local  net.Addr
	remote net.Addr
}

func (c *vsockConn) Read(p []byte) (int, error)         { return c.file.Read(p) }
func (c *vsockConn) Write(p []byte) (int, error)        { return c.file.Write(p) }
func (c *vsockConn) Close() error                       { return c.file.Close() }
func (c *vsockConn) LocalAddr() net.Addr                { return c.local }
func (c *vsockConn) RemoteAddr() net.Addr               { return c.remote }
func (c *vsockConn) SetDeadline(t time.Time) error      { return c.file.SetDeadline(t) }
func (c *vsockConn) SetReadDeadline(t time.Time) error  { return c.file.SetReadDeadline(t) }
func (c *vsockConn) SetWriteDeadline(t time.Time) error { return c.file.SetWriteDeadline(t) }

var _ net.Conn = (*vsockConn)(nil)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "guest loopback listen address")
	cid := flag.Int("cid", 2, "host vsock context id")
	port := flag.Int("port", 1027, "host vsock port")
	unixSocket := flag.String("unix-socket", "", "host unix socket (test/preview transport)")
	serviceHost := flag.String("service-host", "", "upstream host the broker authorizes")
	var routes routeFlags
	flag.Var(&routes, "route", "service=upstream-host:guest-port (repeat for multiple fixed services)")
	flag.Parse()
	dial := func(ctx context.Context) (net.Conn, error) {
		if *unixSocket != "" {
			var d net.Dialer
			return d.DialContext(ctx, "unix", *unixSocket)
		}
		return dialVsock(ctx, *cid, *port)
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) },
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := serveConfigured(ctx, *listen, *serviceHost, routes, transport, dial)
	stop()
	if err != nil {
		log.Fatal(err)
	}
}

func serveConfigured(ctx context.Context, listen, serviceHost string, routes []string, transport http.RoundTripper, rawDial ...func(context.Context) (net.Conn, error)) error {
	dialTunnel := firstTunnelDialer(rawDial)
	if dialTunnel != nil {
		if err := bootstrapProxyTrust(ctx, serviceHost, routes, transport); err != nil {
			// Do not kill the sandbox when the CA bootstrap fails: dockerd can
			// still start, and the failure is logged without credentials.
			log.Printf("bootstrap registry proxy trust: %v", err)
		}
	}
	if len(routes) == 0 {
		if serviceHost == "" {
			return errors.New("service-host is required when no routes are configured")
		}
		return runSingle(ctx, listen, serviceHost, transport, dialTunnel)
	}
	if serviceHost != "" || listen != "127.0.0.1:0" || len(routes) < 2 || len(routes) > 32 {
		return errors.New("multi-route mode requires two to 32 routes and no legacy listener or service host")
	}
	parsed, err := parseProxyRoutes(routes)
	if err != nil {
		return err
	}
	servers := make([]proxyServer, 0, len(parsed))
	ports := make(map[uint16]struct{}, len(parsed))
	for _, route := range parsed {
		if _, exists := ports[route.port]; exists {
			closeProxyServers(servers)
			return errors.New("proxy routes contain a duplicate guest port")
		}
		ports[route.port] = struct{}{}
		listener, listenErr := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(route.port))))
		if listenErr != nil {
			closeProxyServers(servers)
			return fmt.Errorf("listen for proxy route: %w", listenErr)
		}
		server := newHTTPServer(listener.Addr().String(), newRouteHandlerWithDial(route.service, route.host, transport, dialTunnel))
		servers = append(servers, proxyServer{listener: listener, server: server})
		log.Printf("proxy helper listening on %s for configured service", listener.Addr())
	}
	return serveAll(ctx, servers)
}

const (
	proxyCAFile = "/tmp/rheic-proxy-ca-bundle.pem"
	caPath      = "/__rheic/proxy/ca/"
)

func bootstrapProxyTrust(ctx context.Context, serviceHost string, routes []string, transport http.RoundTripper) error {
	hosts := []string{serviceHost}
	if len(routes) > 0 {
		parsed, err := parseProxyRoutes(routes)
		if err != nil {
			return err
		}
		hosts = hosts[:0]
		for _, route := range parsed {
			hosts = append(hosts, route.host)
		}
	}
	services := []string{""}
	if len(routes) > 0 {
		parsed, err := parseProxyRoutes(routes)
		if err != nil {
			return err
		}
		services = services[:0]
		for _, route := range parsed {
			services = append(services, route.service)
		}
	}
	for _, service := range services {
		cert, err := fetchProxyCAForService(ctx, transport, service)
		if err != nil {
			return fmt.Errorf("fetch proxy CA for service %q: %w", service, err)
		}
		if len(cert) == 0 {
			// The broker returns 404 for routes without a registry CA (for
			// example plain HTTP service proxies); keep looking.
			continue
		}
		if err := installProxyCA(cert); err != nil {
			return fmt.Errorf("install proxy CA for service %q: %w", service, err)
		}
		return nil
	}
	return nil
}

func fetchProxyCAForService(ctx context.Context, transport http.RoundTripper, service string) ([]byte, error) {
	token, err := fetchTokenForService(ctx, transport, service)
	if err != nil {
		return nil, err
	}
	defer clear([]byte(token))
	path := caPath
	if service != "" {
		path += service
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://broker"+path, http.NoBody)
	if err != nil {
		return nil, err
	}
	request.Header.Set(tokenHeader, token)
	response, err := transport.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	return readProxyCAResponse(response)
}

func readProxyCAResponse(response *http.Response) ([]byte, error) {
	if response.StatusCode != http.StatusOK || response.ContentLength > 16<<10 {
		return nil, errors.New("registry proxy CA response is invalid")
	}
	cert, err := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
	if err != nil || len(cert) == 0 || len(cert) > 16<<10 {
		clear(cert)
		return nil, errors.New("registry proxy CA response exceeds limits")
	}
	block, rest := pem.Decode(cert)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		clear(cert)
		return nil, errors.New("registry proxy CA response is not a single certificate")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !parsed.IsCA || parsed.KeyUsage&x509.KeyUsageCertSign == 0 {
		clear(cert)
		return nil, errors.New("registry proxy certificate is not a CA")
	}
	return cert, nil
}

func installProxyCA(ca []byte) error {
	system, err := readSystemCABundle()
	if err != nil {
		return err
	}
	if len(system) == 0 {
		return errors.New("read system CA bundle: no supported bundle found")
	}
	bundle := make([]byte, 0, len(system)+len(ca)+2)
	bundle = append(bundle, system...)
	if bundle[len(bundle)-1] != '\n' {
		bundle = append(bundle, '\n')
	}
	bundle = append(bundle, ca...)
	temporary, err := os.CreateTemp(filepath.Dir(proxyCAFile), ".rheic-ca-*")
	if err != nil {
		clear(bundle)
		return err
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		clear(bundle)
		return err
	}
	if _, err := temporary.Write(bundle); err != nil {
		_ = temporary.Close()
		clear(bundle)
		return err
	}
	clear(bundle)
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, proxyCAFile)
}

func readSystemCABundle() ([]byte, error) {
	var failures []error
	for _, read := range []func() ([]byte, error){
		func() ([]byte, error) { return os.ReadFile("/etc/ssl/certs/ca-certificates.crt") },
		func() ([]byte, error) { return os.ReadFile("/etc/ssl/cert.pem") },
		func() ([]byte, error) { return os.ReadFile("/etc/pki/tls/certs/ca-bundle.crt") },
	} {
		data, err := read()
		if err == nil && len(data) > 0 {
			return data, nil
		}
		if err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) != 0 {
		return nil, fmt.Errorf("read system CA bundle: %w", errors.Join(failures...))
	}
	return nil, nil
}

func runSingle(ctx context.Context, listen, serviceHost string, transport http.RoundTripper, rawDial ...func(context.Context) (net.Conn, error)) error {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Printf("proxy helper listening on %s for %s", listener.Addr(), serviceHost)
	return serve(ctx, listener, newHTTPServer(listen, newRouteHandlerWithDial("", serviceHost, transport, firstTunnelDialer(rawDial))))
}

func firstTunnelDialer(dialers []func(context.Context) (net.Conn, error)) func(context.Context) (net.Conn, error) {
	if len(dialers) == 0 {
		return nil
	}
	return dialers[0]
}

func parseProxyRoutes(values []string) ([]proxyRoute, error) {
	routes := make([]proxyRoute, 0, len(values))
	services := make(map[string]struct{}, len(values))
	for _, value := range values {
		service, target, ok := strings.Cut(value, "=")
		if !ok || !validRouteService(service) {
			return nil, errors.New("invalid proxy route service")
		}
		host, portString, ok := strings.Cut(target, ":")
		if !ok || !validServiceHost(host) || strings.Contains(portString, ":") {
			return nil, errors.New("invalid proxy route host or port")
		}
		port, err := strconv.ParseUint(portString, 10, 16)
		if err != nil || port < 1024 {
			return nil, errors.New("proxy route port must be between 1024 and 65535")
		}
		if _, exists := services[service]; exists {
			return nil, errors.New("duplicate proxy route service")
		}
		services[service] = struct{}{}
		routes = append(routes, proxyRoute{service: service, host: host, port: uint16(port)})
	}
	return routes, nil
}

func validRouteService(service string) bool {
	if service == "" || len(service) > 64 {
		return false
	}
	for _, char := range service {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
			continue
		}
		return false
	}
	return true
}

func validServiceHost(host string) bool {
	if host == "" || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, char := range host {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '.' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func newHTTPServer(listen string, handler http.Handler) *http.Server {
	return &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
}

func serve(ctx context.Context, listener net.Listener, server *http.Server) error {
	return serveAll(ctx, []proxyServer{{listener: listener, server: server}})
}

type proxyServer struct {
	listener net.Listener
	server   *http.Server
}

func serveAll(ctx context.Context, servers []proxyServer) error {
	if len(servers) == 0 {
		return errors.New("proxy helper has no listeners")
	}
	serveErr := make(chan error, len(servers))
	for _, current := range servers {
		current := current
		go func() { serveErr <- current.server.Serve(current.listener) }()
	}
	select {
	case err := <-serveErr:
		closeProxyServers(servers)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var failures []error
		for _, current := range servers {
			if err := current.server.Shutdown(shutdownCtx); err != nil {
				failures = append(failures, err)
				_ = current.server.Close()
			}
		}
		for range servers {
			err := <-serveErr
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				failures = append(failures, err)
			}
		}
		return errors.Join(failures...)
	}
}

func closeProxyServers(servers []proxyServer) {
	for _, current := range servers {
		_ = current.server.Close()
		_ = current.listener.Close()
	}
}

func fetchToken(ctx context.Context, transport http.RoundTripper) (string, error) {
	return fetchTokenForService(ctx, transport, "")
}

func fetchTokenForService(ctx context.Context, transport http.RoundTripper, service string) (string, error) {
	path := "/__rheic/proxy/token"
	if service != "" {
		if !validRouteService(service) {
			return "", errors.New("invalid proxy service")
		}
		path += "/" + service
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://broker"+path, http.NoBody)
	if err != nil {
		return "", err
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		return "", errors.New("proxy bootstrap was denied")
	}
	token, err := io.ReadAll(io.LimitReader(response.Body, 65))
	if err != nil || len(token) != 64 {
		return "", errors.New("proxy bootstrap returned an invalid token")
	}
	decoded := make([]byte, hex.DecodedLen(len(token)))
	if _, err := hex.Decode(decoded, token); err != nil {
		return "", errors.New("proxy bootstrap returned an invalid token")
	}
	return string(token), nil
}

func newHandler(serviceHost string, transport http.RoundTripper) http.Handler {
	return newRouteHandler("", serviceHost, transport)
}

func newRouteHandler(service, serviceHost string, transport http.RoundTripper) http.Handler {
	return newRouteHandlerWithDial(service, serviceHost, transport, nil)
}

func newRouteHandlerWithDial(service, serviceHost string, transport http.RoundTripper, dial func(context.Context) (net.Conn, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			if dial == nil || !allowedConnectTarget(serviceHost, r.Host) {
				http.Error(w, "connect target is not supported", http.StatusForbidden)
				return
			}
			serveConnectTunnel(w, r, service, dial, transport)
			return
		}
		out := r.Clone(r.Context())
		out.RequestURI = ""
		out.URL.Scheme = "http"
		out.URL.Host = serviceHost
		out.Host = serviceHost
		token, err := fetchTokenForService(r.Context(), transport, service)
		if err != nil {
			http.Error(w, "proxy bootstrap unavailable", http.StatusBadGateway)
			return
		}
		out.Header.Set(tokenHeader, token)
		out.Header.Del(serviceHeader)
		if service != "" {
			out.Header.Set(serviceHeader, service)
		}
		out.Header.Del("Proxy-Connection")
		out.Header.Del("Proxy-Authorization")
		resp, err := transport.RoundTrip(out)
		if err != nil {
			http.Error(w, "proxy upstream request unavailable", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		for name, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

func allowedConnectTarget(routeHost, target string) bool {
	host, port, err := net.SplitHostPort(target)
	if err != nil || port != "443" || strings.ContainsAny(target, "@/?#\\") {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if strings.EqualFold(routeHost, "registry-1.docker.io") {
		return host == "registry-1.docker.io" || host == "auth.docker.io" || host == "production.cloudfront.docker.com"
	}
	return strings.EqualFold(host, routeHost)
}

func serveConnectTunnel(w http.ResponseWriter, r *http.Request, service string, dial func(context.Context) (net.Conn, error), transport http.RoundTripper) {
	clientConn, clientReader, err := hijackConnectClient(w)
	if err != nil {
		return
	}
	defer func() { _ = clientConn.Close() }()
	ctx := r.Context()
	channel, err := dial(ctx)
	if err != nil {
		_ = writeConnectError(clientConn, http.StatusBadGateway)
		return
	}
	defer func() { _ = channel.Close() }()
	token, err := fetchTokenForService(ctx, transport, service)
	if err != nil {
		_ = writeConnectError(clientConn, http.StatusBadGateway)
		return
	}
	defer clear([]byte(token))
	if err := writeHostConnect(channel, service, r.Host, token); err != nil {
		_ = writeConnectError(clientConn, http.StatusBadGateway)
		return
	}
	channelReader := bufio.NewReader(channel)
	connectRequest := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: r.Host}, Host: r.Host}
	response, err := http.ReadResponse(channelReader, connectRequest)
	if err != nil {
		_ = writeConnectError(clientConn, http.StatusBadGateway)
		return
	}
	if response.StatusCode != http.StatusOK {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		_ = writeConnectError(clientConn, response.StatusCode)
		return
	}
	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	copyTunnel(ctx, clientConn, clientReader, channel, channelReader)
}

func hijackConnectClient(w http.ResponseWriter) (net.Conn, *bufio.Reader, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "connect tunnel unavailable", http.StatusInternalServerError)
		return nil, nil, errors.New("HTTP hijacking is unavailable")
	}
	conn, reader, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	return conn, reader.Reader, nil
}

func writeHostConnect(conn net.Conn, service, target, token string) error {
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	request.Header.Set(tokenHeader, token)
	if service != "" {
		request.Header.Set(serviceHeader, service)
	}
	request.Header.Set("Connection", "keep-alive")
	return request.Write(conn)
}

func writeConnectError(conn net.Conn, status int) error {
	return (&http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Connection": []string{"close"}}, Body: http.NoBody}).Write(conn)
}

func copyTunnel(ctx context.Context, guest net.Conn, guestReader *bufio.Reader, host net.Conn, hostReader *bufio.Reader) {
	done := make(chan struct{}, 2)
	copyStream := func(dst io.Writer, src io.Reader) { _, _ = io.Copy(dst, src); done <- struct{}{} }
	go copyStream(host, guestReader)
	go copyStream(guest, hostReader)
	select {
	case <-ctx.Done():
	case <-done:
	}
	_ = guest.Close()
	_ = host.Close()
	<-done
}

func dialVsock(ctx context.Context, cid, port int) (net.Conn, error) {
	if cid < 0 || uint64(cid) > uint64(^uint32(0)) || port < 1 || port > 65535 {
		return nil, errors.New("vsock address out of range")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ensureVsockDevice(); err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(afVsock, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	sa := sockaddrVM{Family: afVsock, Port: uint32(port), CID: uint32(cid)}
	if err := connectVSock(ctx, fd, sa); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "vsock")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("wrap vsock socket")
	}
	return &vsockConn{
		file:   file,
		local:  vsockAddr{},
		remote: vsockAddr{cid: uint32(cid), port: uint32(port)}, // values were range-checked above.
	}, nil
}

func connectVSock(ctx context.Context, fd int, sa sockaddrVM) error {
	//nolint:gosec // syscall connect requires the sockaddr pointer.
	_, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa))
	if errno != 0 && errno != syscall.EINPROGRESS && errno != syscall.EALREADY && errno != syscall.EAGAIN && errno != syscall.EINTR {
		return fmt.Errorf("vsock connect: %w", errno)
	}
	if errno != 0 {
		if err := waitForVSockConnect(ctx, fd); err != nil {
			return err
		}
	}
	return nil
}

func waitForVSockConnect(ctx context.Context, fd int) error {
	if fd < 0 || uint64(fd) > uint64(^uint32(0)>>1) {
		return errors.New("vsock file descriptor out of range")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		pollFD := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, err := unix.Poll(pollFD, 100)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("wait for vsock connection: %w", err)
		}
		if n == 0 {
			continue
		}
		socketErr, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
		if err != nil {
			return fmt.Errorf("check vsock connection: %w", err)
		}
		if socketErr != 0 {
			return fmt.Errorf("vsock connect: %w", syscall.Errno(socketErr))
		}
		return nil
	}
}

// ensureVsockDevice creates /dev/vsock from the dynamic misc minor.
func ensureVsockDevice() error {
	if _, err := os.Stat("/dev/vsock"); err == nil {
		return nil
	}
	data, err := os.ReadFile("/proc/misc")
	if err != nil {
		return err
	}
	minor := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == "vsock" {
			minor, _ = strconv.Atoi(fields[0])
		}
	}
	if minor == 0 {
		return errors.New("vsock misc device not found")
	}
	return syscall.Mknod("/dev/vsock", syscall.S_IFCHR|0o666, (10<<8)|minor)
}
