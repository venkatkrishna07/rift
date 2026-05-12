package ui

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

const logo = `██████╗ ██╗███████╗████████╗
██╔══██╗██║██╔════╝╚══██╔══╝
██████╔╝██║█████╗     ██║
██╔══██╗██║██╔══╝     ██║
██║  ██║██║██║        ██║
╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   `

var (
	accent = lipgloss.AdaptiveColor{Light: "#06B6D4", Dark: "#67E8F9"}
	muted  = lipgloss.AdaptiveColor{Light: "#6B6B6B", Dark: "#9A9A9A"}
	body   = lipgloss.AdaptiveColor{Light: "#1A1A1A", Dark: "#FAFAFA"}
	good   = lipgloss.AdaptiveColor{Light: "#1F9E5F", Dark: "#73F59F"}
	warn   = lipgloss.AdaptiveColor{Light: "#B8860B", Dark: "#FFD866"}

	logoStyle = lipgloss.NewStyle().Foreground(accent).Bold(true)

	taglineStyle = lipgloss.NewStyle().Foreground(muted).Italic(true)

	pillBase = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#0A0A0A")).
			Bold(true).
			Padding(0, 2).
			MarginLeft(0)
	serverPill = pillBase.Background(lipgloss.AdaptiveColor{Light: "#06B6D4", Dark: "#67E8F9"})
	clientPill = pillBase.Background(lipgloss.AdaptiveColor{Light: "#059669", Dark: "#34D399"})

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(accent).
			Padding(0, 2)

	keyStyle = lipgloss.NewStyle().Foreground(accent).Bold(true).Width(10)
	valStyle = lipgloss.NewStyle().Foreground(body)

	readyStyle  = lipgloss.NewStyle().Foreground(good).Bold(true)
	devStyle    = lipgloss.NewStyle().Foreground(warn).Bold(true)
	indentStyle = lipgloss.NewStyle().PaddingLeft(2)
)

type ServerBanner struct {
	Version  string
	Domain   string
	Listen   string
	HTTPAddr string
	TLS      string
	Mode     string
}

type ClientBanner struct {
	Version    string
	Server     string
	Protocol   string
	NumTunnels int
}

func PrintServer(w io.Writer, b ServerBanner) {
	if !shouldRender() {
		printPlainServer(w, b)
		return
	}
	fmt.Fprintln(w, renderServer(b))
}

func PrintClient(w io.Writer, b ClientBanner) {
	if !shouldRender() {
		printPlainClient(w, b)
		return
	}
	fmt.Fprintln(w, renderClient(b))
}

func shouldRender() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if v := os.Getenv("RIFT_NO_BANNER"); v == "1" || strings.EqualFold(v, "true") {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}

func renderServer(b ServerBanner) string {
	header := lipgloss.JoinVertical(lipgloss.Left,
		logoStyle.Render(logo),
		taglineStyle.Render("self-hosted QUIC tunnel"),
		"",
		serverPill.Render("SERVER"),
	)

	rows := []kv{
		{"version", b.Version},
		{"domain", b.Domain},
		{"listen", b.Listen},
		{"http", b.HTTPAddr},
		{"tls", b.TLS},
		{"mode", b.Mode},
	}
	box := boxStyle.Render(renderRows(rows))

	status := readyStyle.Render("✓ ready · waiting for clients")
	if strings.EqualFold(b.Mode, "dev") {
		status = devStyle.Render("⚠ dev mode · self-signed cert · auth disabled")
	}

	return indent(lipgloss.JoinVertical(lipgloss.Left, "", header, "", box, "", status))
}

func renderClient(b ClientBanner) string {
	header := lipgloss.JoinVertical(lipgloss.Left,
		logoStyle.Render(logo),
		taglineStyle.Render("self-hosted QUIC tunnel"),
		"",
		clientPill.Render("CLIENT"),
	)

	rows := []kv{
		{"version", b.Version},
		{"server", b.Server},
		{"protocol", b.Protocol},
		{"tunnels", fmt.Sprintf("%d", b.NumTunnels)},
	}
	box := boxStyle.Render(renderRows(rows))
	return indent(lipgloss.JoinVertical(lipgloss.Left, "", header, "", box))
}

type kv struct{ k, v string }

func renderRows(rows []kv) string {
	var lines []string
	for _, r := range rows {
		if r.v == "" {
			continue
		}
		lines = append(lines, keyStyle.Render(r.k)+valStyle.Render(r.v))
	}
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func indent(s string) string {
	return indentStyle.Render(s)
}

func printPlainServer(w io.Writer, b ServerBanner) {
	fmt.Fprintln(w, "rift [SERVER] — self-hosted QUIC tunnel")
	plainKV(w, "version", b.Version)
	plainKV(w, "domain", b.Domain)
	plainKV(w, "listen", b.Listen)
	plainKV(w, "http", b.HTTPAddr)
	plainKV(w, "tls", b.TLS)
	plainKV(w, "mode", b.Mode)
	if strings.EqualFold(b.Mode, "dev") {
		fmt.Fprintln(w, "warning: dev mode — self-signed cert, auth disabled")
	} else {
		fmt.Fprintln(w, "ready, waiting for clients")
	}
}

func printPlainClient(w io.Writer, b ClientBanner) {
	fmt.Fprintln(w, "rift [CLIENT] — self-hosted QUIC tunnel")
	plainKV(w, "version", b.Version)
	plainKV(w, "server", b.Server)
	plainKV(w, "protocol", b.Protocol)
	fmt.Fprintf(w, "  %-10s%d\n", "tunnels", b.NumTunnels)
}

func plainKV(w io.Writer, k, v string) {
	if v == "" {
		return
	}
	fmt.Fprintf(w, "  %-10s%s\n", k, v)
}
