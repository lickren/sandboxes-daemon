// Package daemon contains the local control plane.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	runtime "github.com/rheic/sandboxes-runtime"
	"google.golang.org/grpc"

	"github.com/rheic/sandboxes-daemon/internal/oauthsession"
	"github.com/rheic/sandboxes-daemon/internal/registrycredentials"
	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
	"github.com/rheic/sandboxes-daemon/internal/server"
	"github.com/rheic/sandboxes-daemon/internal/service"
	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

// Config is the daemon configuration.
type Config struct {
	SocketPath     string
	StateDir       string
	Backend        runtime.Backend
	DefaultImage   string
	Cleanup        func() error
	OAuthProviders map[string]service.OAuthProvider
	OAuthVault     oauthsession.Vault
	// Settings are optional host-side overrides loaded before the daemon starts.
	DNSUpstream           string
	DefaultPolicyProfile  string
	DefaultCPUs           uint32
	DefaultMemoryMiB      uint32
	DockerVolumeSize      string
	MCPRemoteAllowedHosts []string
	// RegistryPrivate configures one allowlisted private registry reached
	// through the guest registry proxy (ADR-0006).
	RegistryPrivateHost      string
	RegistryPrivateService   string
	RegistryPrivateRealms    []string
	RegistryPrivateRedirects []string
	RegistryPrivateCA        []byte
	// GatewayLost reports sandboxes whose gateway exited unexpectedly.
	GatewayLost     <-chan string
	ProxyHelperPath string
}

// configureService applies host configuration, wires credential storage and
// starts the gateway-loss watcher.
func configureService(ctx context.Context, cfg *Config, svc *service.Service) (func() error, error) {
	applyConfig(svc, *cfg)
	svc.SetSecretProxyRuntime(cfg.ProxyHelperPath, "/tmp")
	credentialCleanup, err := configureCredentialStores(svc)
	if err != nil {
		return nil, err
	}
	if cfg.RegistryPrivateHost != "" {
		if err := svc.SetPrivateRegistry(cfg.RegistryPrivateHost, cfg.RegistryPrivateService, cfg.RegistryPrivateRealms, cfg.RegistryPrivateRedirects, cfg.RegistryPrivateCA); err != nil {
			return nil, err
		}
	}
	if cfg.DefaultImage != "" {
		svc.DefaultImage = cfg.DefaultImage
	}
	configureDockerVolume(svc, cfg.StateDir)
	if cfg.GatewayLost != nil {
		go recoverLostGateways(ctx, svc, cfg.GatewayLost)
	}
	return credentialCleanup, nil
}

// recoverLostGateways stops sandboxes whose gateway exited: the guest packet
// socket points at the dead process, so the sandbox cannot reach the network
// until it is started again.
func recoverLostGateways(ctx context.Context, svc *service.Service, events <-chan string) {
	for {
		select {
		case <-ctx.Done():
			return
		case name := <-events:
			stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			err := svc.StopSandboxByName(stopCtx, name)
			cancel()
			if err != nil {
				slog.Error("stop sandbox after gateway loss", "sandbox", name, "error", err)
				continue
			}
			slog.Warn("sandbox stopped after gateway loss", "sandbox", name)
		}
	}
}

// Run starts the daemon and blocks until ctx is canceled.
//
//nolint:gocritic // Config is constructed once at the process boundary; copying it is intentional.
func Run(ctx context.Context, cfg Config) (runErr error) {
	if cfg.SocketPath == "" || cfg.StateDir == "" {
		return fmt.Errorf("socket path and state dir are required")
	}
	if err := prepareDaemonStateDirectory(cfg.StateDir); err != nil {
		return fmt.Errorf("prepare state dir: %w", err)
	}
	lock, err := lockStateDirectory(cfg.StateDir)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	defer func() { runErr = errors.Join(runErr, runCleanup(cfg.Cleanup)) }()
	st, err := store.Open(ctx, filepath.Join(cfg.StateDir, "sandboxes.db"))
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	svc := service.New(st, cfg.Backend)
	defer func() { runErr = errors.Join(runErr, svc.Close()) }()
	credentialCleanup, err := configureService(ctx, &cfg, svc)
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, credentialCleanup()) }()
	changed, err := svc.Reconcile(ctx)
	if err != nil {
		return fmt.Errorf("reconcile: %w", err)
	}
	if changed > 0 {
		slog.Info("reconciled interrupted state", "records", changed)
	}
	lis, err := listenDaemon(ctx, cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen local daemon endpoint: %w", err)
	}

	// The MCP contract caps JSON results at 4 MiB. Allow bounded protobuf
	// framing overhead while keeping all daemon responses size-limited.
	grpcServer := grpc.NewServer(grpc.MaxSendMsgSize(5 << 20))
	defer grpcServer.Stop()
	registerLocalServices(grpcServer, svc)

	runDone := make(chan struct{})
	defer close(runDone)
	go stopGRPCOnCancel(ctx, runDone, grpcServer)

	slog.Info("daemon listening", "socket", cfg.SocketPath, "state", cfg.StateDir)
	if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

//nolint:gocritic // Config is a value object assembled by the caller.
func applyConfig(svc *service.Service, cfg Config) {
	if cfg.DefaultCPUs != 0 {
		svc.DefaultCPUs = cfg.DefaultCPUs
	}
	if cfg.DefaultMemoryMiB != 0 {
		svc.DefaultMemoryMiB = cfg.DefaultMemoryMiB
	}
	svc.DefaultPolicyProfile = cfg.DefaultPolicyProfile
	svc.SetMCPRemoteAllowlist(cfg.MCPRemoteAllowedHosts)
	if cfg.DockerVolumeSize != "" {
		svc.DockerVolumeSize = cfg.DockerVolumeSize
	}
	configureOAuth(svc, cfg)
}

func configureCredentialStores(svc *service.Service) (func() error, error) {
	registryCredentialStore, err := registrycredentials.NewStore(registrycredentials.NativeVault{})
	if err != nil {
		return nil, fmt.Errorf("create registry credential store: %w", err)
	}
	svc.SetRegistryCredentialStore(registryCredentialStore)
	serviceSecretStore, err := servicesecrets.NewStore(servicesecrets.NativeVault{})
	if err != nil {
		return nil, fmt.Errorf("create service secret store: %w", err)
	}
	svc.SetServiceSecretStore(serviceSecretStore)
	proxyManager := secretproxy.New()
	svc.SetSecretProxyManager(proxyManager)
	return proxyManager.Close, nil
}

func registerLocalServices(grpcServer *grpc.Server, svc *service.Service) {
	localv1.RegisterSandboxServiceServer(grpcServer, server.NewSandbox(svc))
	localv1.RegisterOperationServiceServer(grpcServer, server.NewOperation(svc))
	localv1.RegisterRegistryCredentialServiceServer(grpcServer, server.NewRegistryCredential(svc))
	localv1.RegisterAccountServiceServer(grpcServer, server.NewAccount(svc))
	localv1.RegisterSecretServiceServer(grpcServer, server.NewSecret(svc))
}

//nolint:gocritic // Config is a value object assembled by the caller.
func configureOAuth(svc *service.Service, cfg Config) {
	svc.SetOAuthProviders(cfg.OAuthProviders)
	if cfg.OAuthVault != nil {
		svc.SetOAuthVault(cfg.OAuthVault)
	}
}

func runCleanup(cleanup func() error) error {
	if cleanup == nil {
		return nil
	}
	return cleanup()
}

func stopGRPCOnCancel(ctx context.Context, runDone <-chan struct{}, grpcServer *grpc.Server) {
	select {
	case <-runDone:
		return
	case <-ctx.Done():
	}
	graceDone := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(graceDone)
	}()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-graceDone:
	case <-timer.C:
		grpcServer.Stop()
	}
}

func configureDockerVolume(svc *service.Service, stateDir string) {
	svc.DockerVolumeDir = filepath.Join(stateDir, "docker")
	if svc.DockerVolumeSize == "" {
		svc.DockerVolumeSize = "10g"
	}
	if svc.MkfsExt4 == "" {
		svc.MkfsExt4 = "mkfs.ext4"
	}
	if value := os.Getenv("DOCKER_SANDBOXES_DOCKER_SIZE"); value != "" {
		svc.DockerVolumeSize = value
	}
	if value := os.Getenv("DOCKER_SANDBOXES_MKFS_EXT4"); value != "" {
		svc.MkfsExt4 = value
	}
}
