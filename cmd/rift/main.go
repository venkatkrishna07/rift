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

	"go.uber.org/zap"

	"github.com/venkatkrishna07/rift/internal/version"
	"github.com/venkatkrishna07/rift"
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
	case "version":
		fmt.Println(version.String())
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
	_ = fs.Parse(args)

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
	return runWithSignal(srv.Run)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func runClient(args []string, log *zap.Logger) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	srvAddr := fs.String("server", "", "rift server host or host:port (required)")
	insecure := fs.Bool("insecure", false, "Skip TLS cert verification (dev mode)")
	forceInsecure := fs.Bool("force-insecure", false, "Allow --insecure with non-localhost servers")
	tokenArg := fs.String("token", "", "Auth token (overrides DB lookup)")
	dbPath := fs.String("db", defaultClientDB(log), "BadgerDB data directory")
	protocol := fs.String("protocol", "rift", "Wire protocol: rift or mcp")
	clientStreamTimeout := fs.Duration("stream-timeout", rift.DefaultStreamTimeout,
		"Data stream idle timeout; stream closed after this much inactivity (default 5m)")
	var exposeFlags multiFlag
	fs.Var(&exposeFlags, "expose", "PORT:PROTO[:NAME], e.g. 3000:http:myapp (repeatable)")
	_ = fs.Parse(args)

	if *srvAddr == "" {
		return fmt.Errorf("--server is required")
	}
	if len(exposeFlags) == 0 {
		return fmt.Errorf("at least one --expose flag is required")
	}
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
		StreamTimeout:       *clientStreamTimeout,
		Protocol:            *protocol,
	}
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
	return runWithSignal(c.Connect)
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
  rift version          Print version

Server flags:
  --domain string       Base domain (default: tunnel.localhost)
  --listen string       Listen addr — QUIC=UDP, HTTPS=TCP (default: :443)
  --http string         HTTP listen addr for ACME HTTP-01 challenges (default: :80)
  --dev                 Dev mode: self-signed cert, no auth required
  --cert / --key        Pre-provisioned TLS cert+key PEM files
  --db string           BadgerDB data dir (default: /var/lib/rift/db)
  --add-token string    Provision a token for NAME and exit
  --admin-secret string Bearer secret for /_admin/tokens (or $RIFT_ADMIN_SECRET)

Client flags:
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
// existing zap logger through pkg/rift options without forcing zap into the
// public API.
type zapRiftLogger struct{ log *zap.Logger }

func (z zapRiftLogger) Debug(msg string, kv ...any) { z.log.Sugar().Debugw(msg, kv...) }
func (z zapRiftLogger) Info(msg string, kv ...any)  { z.log.Sugar().Infow(msg, kv...) }
func (z zapRiftLogger) Warn(msg string, kv ...any)  { z.log.Sugar().Warnw(msg, kv...) }
func (z zapRiftLogger) Error(msg string, kv ...any) { z.log.Sugar().Errorw(msg, kv...) }
