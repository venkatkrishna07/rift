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

	"github.com/venkatkrishna07/rift/internal/client"
	"github.com/venkatkrishna07/rift/internal/config"
	"github.com/venkatkrishna07/rift/internal/proto"
	"github.com/venkatkrishna07/rift/internal/server"
	"github.com/venkatkrishna07/rift/internal/store"
	"github.com/venkatkrishna07/rift/internal/version"
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
	domain  := fs.String("domain", "tunnel.localhost", "Base domain for HTTP tunnels")
	listen  := fs.String("listen", ":443", "Listen address (QUIC=UDP, HTTPS=TCP share this port)")
	httpAddr := fs.String("http", ":80", "HTTP listen address for ACME HTTP-01 challenges (prod only)")
	dev     := fs.Bool("dev", false, "Dev mode: self-signed cert, no token auth")
	certF   := fs.String("cert", "", "TLS cert PEM (pre-provisioned wildcard cert)")
	keyF    := fs.String("key", "", "TLS key PEM (required with --cert)")
	dbPath        := fs.String("db", "/var/lib/rift/db", "BadgerDB data directory")
	addTok        := fs.String("add-token", "", "Provision a token for NAME, print it, and exit")
	maxBodyBytes  := fs.Int64("max-body-bytes", config.DefaultMaxBodyBytes,
		"Max HTTP request/response body size in bytes (default 100 MiB)")
	streamTimeout := fs.Duration("stream-timeout", config.DefaultStreamTimeout,
		"Data stream idle timeout; stream closed after this much inactivity (default 5m)")
	maxConns      := fs.Int("max-conns", config.DefaultMaxTotalConns,
		"Max total concurrent QUIC connections server-wide (default 500)")
	tcpPortMin := fs.Uint("tcp-port-min", uint(config.DefaultTCPPortMin),
		"Lower bound of TCP tunnel port range (default 10000)")
	tcpPortMax := fs.Uint("tcp-port-max", uint(config.DefaultTCPPortMax),
		"Upper bound of TCP tunnel port range (default 65535)")
	adminSecret := fs.String("admin-secret", os.Getenv("RIFT_ADMIN_SECRET"),
		"Bearer secret for /_admin/tokens endpoint (or $RIFT_ADMIN_SECRET)")
	tokenTTL := fs.Duration("token-ttl", config.DefaultTokenTTL,
		"Default token lifetime (default 24h; 0 = no expiry)")
	_ = fs.Parse(args)

	if *dev {
		cfg := zap.NewDevelopmentConfig()
		cfg.DisableStacktrace = true
		devLog, err := cfg.Build()
		if err != nil {
			return fmt.Errorf("init dev logger: %w", err)
		}
		log = devLog
	}

	ts, err := store.OpenBadger(*dbPath)
	if err != nil {
		return fmt.Errorf("open token store: %w", err)
	}
	defer ts.Close()

	if *addTok != "" {
		tok, err := store.GenerateToken()
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
		tlsCfg, err = server.DevTLSConfig(*domain)
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
		tlsCfg, acmeHandler = server.ProdTLSConfig(*domain, filepath.Join(*dbPath, "certs"))
	}

	cfg := config.ServerConfig{
		ListenAddr:    *listen,
		ACMEAddr:      *httpAddr,
		Domain:        *domain,
		Dev:           *dev,
		MaxBodyBytes:  *maxBodyBytes,
		StreamTimeout: *streamTimeout,
		MaxTotalConns: *maxConns,
		TCPPortMin:    uint16(*tcpPortMin),
		TCPPortMax:    uint16(*tcpPortMax),
		AdminSecret:   *adminSecret,
		TokenTTL:      *tokenTTL,
	}
	var authStore store.TokenStore
	if !*dev {
		authStore = ts
	}
	return runWithSignal(server.New(cfg, authStore, tlsCfg, acmeHandler, log).Run)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func runClient(args []string, log *zap.Logger) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	srvAddr  := fs.String("server", "", "rift server host or host:port (required)")
	insecure      := fs.Bool("insecure",       false, "Skip TLS cert verification (dev mode)")
	forceInsecure := fs.Bool("force-insecure", false, "Allow --insecure with non-localhost servers")
	tokenArg      := fs.String("token",        "",    "Auth token (overrides DB lookup)")
	dbPath   := fs.String("db", defaultClientDB(), "BadgerDB data directory")
	clientStreamTimeout := fs.Duration("stream-timeout", config.DefaultStreamTimeout,
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

	specs := make([]config.TunnelSpec, 0, len(exposeFlags))
	for _, e := range exposeFlags {
		spec, err := parseTunnelSpec(e)
		if err != nil {
			return err
		}
		specs = append(specs, spec)
	}

	// Open read-only — multiple clients can run simultaneously without lock conflicts.
	// Returns nil (no error) if the DB doesn't exist yet; --token flag is required in that case.
	var ts store.TokenStore
	if bs, err := store.OpenBadgerReadOnly(*dbPath); err != nil {
		log.Warn("could not open token store, proceeding without saved token", zap.Error(err))
	} else if bs != nil {
		ts = bs
		defer ts.Close()
	}

	cfg := config.ClientConfig{
		Server:        *srvAddr,
		Token:         *tokenArg,
		Tunnels:       specs,
		Insecure:      *insecure,
		ForceInsecure: *forceInsecure,
		StreamTimeout: *clientStreamTimeout,
	}
	c := client.New(cfg, ts, log)
	return runWithSignal(func(ctx context.Context) error {
		c.Connect(ctx)
		return nil
	})
}

func parseTunnelSpec(s string) (config.TunnelSpec, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 2 {
		return config.TunnelSpec{}, fmt.Errorf("invalid --expose %q: want PORT:PROTO[:NAME]", s)
	}
	port, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil || port == 0 {
		return config.TunnelSpec{}, fmt.Errorf("invalid port in --expose %q", s)
	}
	if parts[1] != proto.ProtoHTTP && parts[1] != proto.ProtoTCP {
		return config.TunnelSpec{}, fmt.Errorf("unknown proto %q in --expose %q", parts[1], s)
	}
	var name string
	if len(parts) == 3 {
		name = parts[2]
	}
	return config.TunnelSpec{LocalPort: uint16(port), Proto: parts[1], Name: name}, nil
}

func runWithSignal(fn func(context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return fn(ctx)
}

func defaultClientDB() string {
	home, _ := os.UserHomeDir()
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
