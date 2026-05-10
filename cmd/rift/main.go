package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/venkatkrishna07/rift"
	"github.com/venkatkrishna07/rift/cmd/rift/internal/cliconfig"
	"github.com/venkatkrishna07/rift/cmd/rift/internal/ui"
	"github.com/venkatkrishna07/rift/cmd/rift/internal/version"
)

func main() {
	log, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync() //nolint:errcheck

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "server":
		err = runServer(os.Args[2:], log)
	case "client":
		err = runClient(os.Args[2:], log)
	case "version", "--version", "-v":
		fmt.Println(version.String())
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
	if err != nil {
		log.Fatal("fatal", zap.Error(err))
	}
}

func runServer(args []string, log *zap.Logger) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to TOML config file (or $RIFT_CONFIG)")
	domain := fs.String("domain", "tunnel.localhost", "Base domain for HTTP tunnels")
	listen := fs.String("listen", ":443", "Listen address (QUIC=UDP, HTTPS=TCP share this port)")
	httpAddr := fs.String("http", ":80", "HTTP listen address for ACME HTTP-01 challenges (prod only)")
	dev := fs.Bool("dev", false, "Dev mode: self-signed cert, no token auth")
	certF := fs.String("cert", "", "TLS cert PEM (pre-provisioned wildcard cert)")
	keyF := fs.String("key", "", "TLS key PEM (required with --cert)")
	dbPath := fs.String("db", "/var/lib/rift/db", "BadgerDB data directory")
	addTok := fs.String("add-token", "", "Provision a token for NAME, print it, and exit")
	maxBodyBytes := fs.Int64("max-body-bytes", rift.DefaultMaxBodyBytes,
		"Max HTTP request/response body size in bytes (default 100 MiB)")
	streamTimeout := fs.Duration("stream-timeout", rift.DefaultStreamTimeout,
		"Data stream idle timeout; stream closed after this much inactivity (default 5m)")
	maxConns := fs.Int("max-conns", rift.DefaultMaxTotalConns,
		"Max total concurrent QUIC connections server-wide (default 500)")
	tcpPortMin := fs.Uint("tcp-port-min", uint(rift.DefaultTCPPortMin),
		"Lower bound of TCP tunnel port range (default 10000)")
	tcpPortMax := fs.Uint("tcp-port-max", uint(rift.DefaultTCPPortMax),
		"Upper bound of TCP tunnel port range (default 65535)")
	adminSecret := fs.String("admin-secret", "",
		"Bearer secret for /_admin/tokens endpoint (or $RIFT_ADMIN_SECRET)")
	tokenTTL := fs.Duration("token-ttl", rift.DefaultTokenTTL,
		"Default token lifetime (default 1h; 0 = no expiry)")
	shutdownTimeout := fs.Duration("shutdown-timeout", 10*time.Second,
		"Max time to wait for in-flight tunnels to drain on SIGTERM (default 10s)")
	_ = fs.Parse(args)

	setFlags := flagsExplicitlySet(fs)
	file, err := cliconfig.LoadServerFile(cliconfig.ResolveConfigPath(*configPath))
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if file != nil {
		if err := applyServerFile(file, setFlags, domain, listen, httpAddr, certF, keyF, dbPath,
			maxBodyBytes, streamTimeout, maxConns, tcpPortMin, tcpPortMax, adminSecret, tokenTTL); err != nil {
			return err
		}
	}

	if *adminSecret == "" {
		*adminSecret = os.Getenv("RIFT_ADMIN_SECRET")
	}

	if *dev {
		cfg := zap.NewDevelopmentConfig()
		cfg.DisableStacktrace = true
		devLog, err := cfg.Build()
		if err != nil {
			return fmt.Errorf("init dev logger: %w", err)
		}
		log = devLog
	}

	ts, err := rift.OpenBadgerStore(*dbPath, zapRiftLogger{log: log})
	if err != nil {
		return fmt.Errorf("open token store: %w", err)
	}
	defer func() {
		if err := ts.Close(); err != nil {
			log.Error("close token store", zap.Error(err))
		}
	}()

	if *addTok != "" {
		tok, err := rift.GenerateToken()
		if err != nil {
			return err
		}
		if err := ts.Add(context.Background(), *addTok, tok, *tokenTTL); err != nil {
			return fmt.Errorf("save token: %w", err)
		}
		fmt.Printf("Token for %q:\n%s\n", *addTok, tok)
		return nil
	}

	var (
		tlsCfg      *tls.Config
		acmeHandler http.Handler
	)
	switch {
	case *dev:
		tlsCfg, err = rift.DevTLSConfig(*domain)
		if err != nil {
			return fmt.Errorf("dev TLS: %w", err)
		}
		log.Warn("dev mode active — self-signed cert, auth disabled", zap.String("domain", *domain))
	case *certF != "":
		cert, err := tls.LoadX509KeyPair(*certF, *keyF)
		if err != nil {
			return fmt.Errorf("load cert/key: %w", err)
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	default:
		tlsCfg, acmeHandler = rift.ProdTLSConfig(*domain, filepath.Join(*dbPath, "certs"))
	}

	cfg := rift.ServerConfig{
		ListenAddr:    *listen,
		ACMEAddr:      *httpAddr,
		Domain:        *domain,
		Dev:           *dev,
		MaxBodyBytes:  *maxBodyBytes,
		StreamTimeout: *streamTimeout,
		MaxTotalConns: *maxConns,
		TCPPortMin:    uint16(*tcpPortMin),
		TCPPortMax:    uint16(*tcpPortMax),
		TokenTTL:      *tokenTTL,
	}
	riftLogger := zapRiftLogger{log: log}
	opts := []rift.ServerOption{
		rift.WithTLSConfig(tlsCfg),
		rift.WithLogger(riftLogger),
	}
	if acmeHandler != nil {
		opts = append(opts, rift.WithACMEHandler(acmeHandler))
	}
	if !*dev {
		opts = append(opts, rift.WithTokenStore(ts))
	}
	if *adminSecret != "" {
		ttl := *tokenTTL
		iss := rift.NewAdminSecretIssuer(*adminSecret, ts, ttl, riftLogger)
		opts = append(opts, rift.WithTokenIssuer(iss))
	}
	srv, err := rift.NewServer(cfg, opts...)
	if err != nil {
		return fmt.Errorf("construct server: %w", err)
	}

	ui.PrintServer(os.Stderr, ui.ServerBanner{
		Version:  version.Version,
		Domain:   *domain,
		Listen:   *listen,
		HTTPAddr: *httpAddr,
		TLS:      describeTLS(*dev, *certF),
		Mode:     describeMode(*dev),
	})

	return runWithGracefulShutdown(srv.Run, srv.Shutdown, *shutdownTimeout)
}

func describeTLS(dev bool, certPath string) string {
	switch {
	case dev:
		return "self-signed (dev)"
	case certPath != "":
		return "pre-provisioned cert"
	default:
		return "Let's Encrypt (auto)"
	}
}

func describeMode(dev bool) string {
	if dev {
		return "dev"
	}
	return "production"
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func runClient(args []string, log *zap.Logger) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to TOML config file (or $RIFT_CONFIG)")
	srvAddr := fs.String("server", "", "rift server host or host:port (required)")
	insecure := fs.Bool("insecure", false, "Skip TLS cert verification (dev mode)")
	forceInsecure := fs.Bool("force-insecure", false, "Allow --insecure with non-localhost servers")
	tokenArg := fs.String("token", "", "Auth token (overrides DB lookup)")
	dbPath := fs.String("db", defaultClientDB(log), "BadgerDB data directory")
	protocol := fs.String("protocol", "rift", "Wire protocol: rift or mcp")
	clientStreamTimeout := fs.Duration("stream-timeout", rift.DefaultStreamTimeout,
		"Data stream idle timeout; stream closed after this much inactivity (default 5m)")
	clientShutdownTimeout := fs.Duration("shutdown-timeout", 10*time.Second,
		"Max time to wait for graceful client shutdown on SIGTERM (default 10s)")
	var exposeFlags multiFlag
	fs.Var(&exposeFlags, "expose", "PORT:PROTO[:NAME], e.g. 3000:http:myapp (repeatable)")
	_ = fs.Parse(args)
	if *forceInsecure && os.Getenv("RIFT_FORCE_INSECURE") != "yes" {
		return fmt.Errorf(
			"--force-insecure requires the environment variable RIFT_FORCE_INSECURE=yes " +
				"to prevent accidental TLS verification bypass on production servers",
		)
	}

	specs := make([]rift.TunnelSpec, 0, len(exposeFlags))
	for _, e := range exposeFlags {
		spec, err := parseTunnelSpec(e)
		if err != nil {
			return err
		}
		specs = append(specs, spec)
	}

	setFlags := flagsExplicitlySet(fs)
	file, err := cliconfig.LoadClientFile(cliconfig.ResolveConfigPath(*configPath))
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if file != nil {
		if err := applyClientFile(file, setFlags, srvAddr, tokenArg, dbPath,
			insecure, forceInsecure, clientStreamTimeout, protocol, &specs); err != nil {
			return err
		}
	}

	if *srvAddr == "" {
		return fmt.Errorf("--server is required (or set client.server in config)")
	}
	if len(specs) == 0 {
		return fmt.Errorf("at least one --expose flag or [[tunnels]] entry is required")
	}

	// Open read-only — multiple clients can run simultaneously without lock conflicts.
	// Returns nil (no error) if the DB doesn't exist yet; --token flag is required in that case.
	var ts rift.TokenStore
	if bs, err := rift.OpenBadgerReadOnlyStore(*dbPath, zapRiftLogger{log: log}); err != nil {
		log.Warn("could not open token store, proceeding without saved token", zap.Error(err))
	} else if bs != nil {
		ts = bs
		defer func() {
			if err := ts.Close(); err != nil {
				log.Error("close client token store", zap.Error(err))
			}
		}()
	}

	if *protocol != rift.ProtocolRift && *protocol != rift.ProtocolMCP {
		return fmt.Errorf("--protocol must be 'rift' or 'mcp', got %q", *protocol)
	}

	cfg := rift.ClientConfig{
		Server:              *srvAddr,
		Token:               *tokenArg,
		Tunnels:             specs,
		Insecure:            *insecure,
		AcknowledgeInsecure: *forceInsecure,
		DBPath:              *dbPath,
		StreamTimeout:       *clientStreamTimeout,
		Protocol:            *protocol,
	}

	ui.PrintClient(os.Stderr, ui.ClientBanner{
		Version:    version.Version,
		Server:     *srvAddr,
		Protocol:   *protocol,
		NumTunnels: len(specs),
	})

	clientOpts := []rift.ClientOption{
		rift.WithClientLogger(zapRiftLogger{log: log}),
	}
	if ts != nil {
		clientOpts = append(clientOpts, rift.WithClientTokenStore(ts))
	}
	c, err := rift.NewClient(cfg, clientOpts...)
	if err != nil {
		return fmt.Errorf("construct client: %w", err)
	}
	return runWithGracefulShutdown(
		c.Connect,
		func(context.Context) error { return c.Close() },
		*clientShutdownTimeout,
	)
}

func flagsExplicitlySet(fs *flag.FlagSet) map[string]bool {
	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

func applyServerFile(
	file *cliconfig.FileServer,
	set map[string]bool,
	domain, listen, httpAddr, certF, keyF, dbPath *string,
	maxBodyBytes *int64,
	streamTimeout *time.Duration,
	maxConns *int,
	tcpPortMin, tcpPortMax *uint,
	adminSecret *string,
	tokenTTL *time.Duration,
) error {
	s := file.Server
	if !set["domain"] && s.Domain != "" {
		*domain = s.Domain
	}
	if !set["listen"] && s.Listen != "" {
		*listen = s.Listen
	}
	if !set["http"] && s.HTTP != "" {
		*httpAddr = s.HTTP
	}
	if !set["db"] && s.DB != "" {
		*dbPath = s.DB
	}
	if !set["max-body-bytes"] && s.MaxBodyBytes > 0 {
		*maxBodyBytes = s.MaxBodyBytes
	}
	if !set["max-conns"] && s.MaxConns > 0 {
		*maxConns = s.MaxConns
	}
	if !set["tcp-port-min"] && s.TCPPortMin > 0 {
		*tcpPortMin = uint(s.TCPPortMin)
	}
	if !set["tcp-port-max"] && s.TCPPortMax > 0 {
		*tcpPortMax = uint(s.TCPPortMax)
	}
	if !set["admin-secret"] && s.AdminSecret != "" {
		*adminSecret = s.AdminSecret
	}
	if !set["stream-timeout"] && s.StreamTimeout != "" {
		d, err := cliconfig.ParseDurationStr(s.StreamTimeout)
		if err != nil {
			return fmt.Errorf("server.stream-timeout: %w", err)
		}
		*streamTimeout = d
	}
	if !set["token-ttl"] && s.TokenTTL != "" {
		d, err := cliconfig.ParseDurationStr(s.TokenTTL)
		if err != nil {
			return fmt.Errorf("server.token-ttl: %w", err)
		}
		*tokenTTL = d
	}
	if !set["cert"] && file.TLS.Cert != "" {
		*certF = file.TLS.Cert
	}
	if !set["key"] && file.TLS.Key != "" {
		*keyF = file.TLS.Key
	}
	return nil
}

func applyClientFile(
	file *cliconfig.FileClient,
	set map[string]bool,
	srvAddr, tokenArg, dbPath *string,
	insecure, forceInsecure *bool,
	clientStreamTimeout *time.Duration,
	protocol *string,
	specs *[]rift.TunnelSpec,
) error {
	c := file.Client
	if !set["server"] && c.Server != "" {
		*srvAddr = c.Server
	}
	if !set["token"] && c.Token != "" {
		*tokenArg = c.Token
	}
	if !set["db"] && c.DB != "" {
		*dbPath = cliconfig.ExpandHome(c.DB)
	}
	if !set["insecure"] && c.Insecure != nil {
		*insecure = *c.Insecure
	}
	if !set["force-insecure"] && c.ForceInsecure != nil {
		*forceInsecure = *c.ForceInsecure
	}
	if !set["protocol"] && c.Protocol != "" {
		*protocol = c.Protocol
	}
	if !set["stream-timeout"] && c.StreamTimeout != "" {
		d, err := cliconfig.ParseDurationStr(c.StreamTimeout)
		if err != nil {
			return fmt.Errorf("client.stream-timeout: %w", err)
		}
		*clientStreamTimeout = d
	}
	for i, t := range file.Tunnels {
		if t.LocalPort == 0 {
			return fmt.Errorf("tunnels[%d]: local-port is required", i)
		}
		if t.Proto != rift.ProtoHTTP && t.Proto != rift.ProtoTCP && t.Proto != rift.ProtocolMCP {
			return fmt.Errorf("tunnels[%d]: unknown proto %q", i, t.Proto)
		}
		*specs = append(*specs, rift.TunnelSpec{
			LocalPort: t.LocalPort,
			Proto:     t.Proto,
			Name:      t.Name,
		})
	}
	return nil
}

func parseTunnelSpec(s string) (rift.TunnelSpec, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 2 {
		return rift.TunnelSpec{}, fmt.Errorf("invalid --expose %q: want PORT:PROTO[:NAME]", s)
	}
	port, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil || port == 0 {
		return rift.TunnelSpec{}, fmt.Errorf("invalid port in --expose %q", s)
	}
	if parts[1] != rift.ProtoHTTP && parts[1] != rift.ProtoTCP && parts[1] != rift.ProtocolMCP {
		return rift.TunnelSpec{}, fmt.Errorf("unknown proto %q in --expose %q", parts[1], s)
	}
	var name string
	if len(parts) == 3 {
		name = parts[2]
	}
	return rift.TunnelSpec{LocalPort: uint16(port), Proto: parts[1], Name: name}, nil
}

func runWithSignal(fn func(context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return fn(ctx)
}

func runWithGracefulShutdown(
	runFn func(context.Context) error,
	shutdownFn func(context.Context) error,
	timeout time.Duration,
) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runWithGracefulShutdownCtx(ctx, runFn, shutdownFn, timeout)
}

func runWithGracefulShutdownCtx(
	ctx context.Context,
	runFn func(context.Context) error,
	shutdownFn func(context.Context) error,
	timeout time.Duration,
) error {
	runErr := make(chan error, 1)
	go func() { runErr <- runFn(ctx) }()

	select {
	case err := <-runErr:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := shutdownFn(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	return <-runErr
}

func defaultClientDB(log *zap.Logger) string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Warn("could not determine home directory; token DB will be relative to working directory",
			zap.Error(err))
		return filepath.Join(".local", "share", "rift")
	}
	return filepath.Join(home, ".local", "share", "rift")
}

func printUsage() {
	fmt.Print(`rift — self-hosted QUIC tunnel

Usage:
  rift server [flags]   Start the tunnel server (run on your VPS)
  rift client [flags]   Connect and expose local services
  rift version          Print version (also: --version, -v)
  rift help             Print this message  (also: --help, -h)

Server flags:
  --config string       Path to TOML config file (or $RIFT_CONFIG)
  --domain string       Base domain (default: tunnel.localhost)
  --listen string       Listen addr — QUIC=UDP, HTTPS=TCP (default: :443)
  --http string         HTTP listen addr for ACME HTTP-01 challenges (default: :80)
  --dev                 Dev mode: self-signed cert, no auth required
  --cert / --key        Pre-provisioned TLS cert+key PEM files
  --db string           BadgerDB data dir (default: /var/lib/rift/db)
  --add-token string    Provision a token for NAME and exit
  --admin-secret string Bearer secret for /_admin/tokens (or $RIFT_ADMIN_SECRET)

Client flags:
  --config string       Path to TOML config file (or $RIFT_CONFIG)
  --server string       Server host or host:port (required)
  --expose value        PORT:PROTO[:NAME] e.g. 3000:http:myapp (repeatable)
  --token string        Auth token (overrides DB lookup)
  --db string           BadgerDB data dir (default: ~/.local/share/rift)
  --insecure            Skip TLS cert verification (for --dev server)

Examples:
  rift server --dev --listen :4443
  rift client --server localhost:4443 --insecure --expose 3000:http

  rift server --domain tunnel.example.com --add-token alice
  rift client --server tunnel.example.com --expose 3000:http:myapp --expose 5432:tcp
`)
}

// zapRiftLogger adapts *zap.Logger to rift.Logger so the CLI can pass its
// existing zap logger through rift options without forcing zap into the
// public API.
type zapRiftLogger struct{ log *zap.Logger }

func (z zapRiftLogger) Debug(msg string, kv ...any) { z.log.Sugar().Debugw(msg, kv...) }
func (z zapRiftLogger) Info(msg string, kv ...any)  { z.log.Sugar().Infow(msg, kv...) }
func (z zapRiftLogger) Warn(msg string, kv ...any)  { z.log.Sugar().Warnw(msg, kv...) }
func (z zapRiftLogger) Error(msg string, kv ...any) { z.log.Sugar().Errorw(msg, kv...) }
