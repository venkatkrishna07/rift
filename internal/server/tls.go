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
	"strings"
	"time"

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
func ProdTLSConfig(domain, cacheDir string) (*tls.Config, http.Handler) {
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
	return cfg, m.HTTPHandler(nil)
}
