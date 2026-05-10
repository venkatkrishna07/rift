package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/acme/autocert"
)

// DevTLSConfig generates a self-signed wildcard ECDSA P-256 certificate
// covering domain and *.domain. For development only.
func DevTLSConfig(domain string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate dev key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "*." + domain},
		DNSNames:     []string{domain, "*." + domain},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal dev key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load dev cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ProdTLSConfig returns a *tls.Config and an HTTP handler for Let's Encrypt.
//
// The TLS config uses TLS-ALPN-01 to issue per-subdomain certificates (wildcard
// certs require DNS-01 which needs a DNS provider integration). It accepts the
// apex domain and any single-level subdomain (e.g. foo.tunnel.example.com).
//
// Mount the returned http.Handler on port 80 to enable HTTP-01 as a fallback
// challenge method — this is faster and more reliable than TLS-ALPN-01 alone.
//
// cacheDir is created with mode 0700 if it does not exist. If the directory
// already exists with looser permissions, a warning is logged but the open
// proceeds so existing deployments are not broken. log may be nil.
func ProdTLSConfig(domain, cacheDir string, log *zap.Logger) (*tls.Config, http.Handler) {
	if log == nil {
		log = zap.NewNop()
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		log.Warn("could not prepare ACME cache directory — autocert will retry on first issuance",
			zap.String("path", cacheDir),
			zap.Error(err),
		)
	} else if info, err := os.Stat(cacheDir); err == nil && info.Mode().Perm()&0o077 != 0 {
		log.Warn("ACME cache directory has loose permissions — expected 0700",
			zap.String("path", cacheDir),
			zap.String("mode", fmt.Sprintf("%04o", info.Mode().Perm())),
		)
	}

	suffix := "." + domain
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(cacheDir),
		HostPolicy: func(_ context.Context, host string) error {
			if host == domain {
				return nil
			}
			// Accept any single-level subdomain (e.g. foo.example.com).
			if strings.HasSuffix(host, suffix) && !strings.Contains(host[:len(host)-len(suffix)], ".") {
				return nil
			}
			return fmt.Errorf("host %q not allowed", host)
		},
	}
	cfg := m.TLSConfig()
	cfg.MinVersion = tls.VersionTLS13

	// Wrap GetCertificate so issuance/renewal failures surface in operator
	// logs rather than only emerging when a TLS handshake fails. Successful
	// returns log at debug to avoid spamming production.
	inner := cfg.GetCertificate
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := inner(hello)
		if err != nil {
			log.Warn("ACME certificate issuance failed",
				zap.String("server_name", hello.ServerName),
				zap.Error(err),
			)
			return nil, err
		}
		log.Debug("ACME certificate served",
			zap.String("server_name", hello.ServerName),
			zap.Time("expires", certNotAfter(cert)),
		)
		return cert, nil
	}
	return cfg, m.HTTPHandler(nil)
}

func certNotAfter(c *tls.Certificate) time.Time {
	if c == nil {
		return time.Time{}
	}
	if c.Leaf != nil {
		return c.Leaf.NotAfter
	}
	if len(c.Certificate) == 0 {
		return time.Time{}
	}
	parsed, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return time.Time{}
	}
	return parsed.NotAfter
}
