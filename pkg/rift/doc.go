// Package rift exposes the public Go library API for the rift QUIC tunnel.
//
// rift can be used in two ways:
//
//  1. As a CLI binary — see the `rift` command at cmd/rift/.
//  2. As an embeddable library — import this package and call NewServer or
//     NewClient from your own Go program.
//
// API stability: this package is the only stable surface. Anything under
// internal/ may change without notice.
package rift
