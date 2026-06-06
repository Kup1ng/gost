//go:build !linux
// +build !linux

package gost

import "errors"

// errNATUnsupported is returned for every NAT operation on non-Linux platforms.
// --NAT relies on netfilter (DNAT/conntrack), which only exists on Linux.
var errNATUnsupported = errors.New("--NAT (kernel forwarding) is only supported on Linux")

// NATManager is a no-op placeholder on non-Linux builds so that cmd/gost keeps
// compiling for windows/darwin/freebsd. Any attempt to use it fails clearly.
type NATManager struct{}

// NewNATManager returns a placeholder manager on non-Linux platforms.
func NewNATManager(_ []NATForward, _ NATOptions) *NATManager { return &NATManager{} }

// BackendName reports the selected backend name (none on non-Linux).
func (m *NATManager) BackendName() string { return "" }

// Setup always fails on non-Linux platforms.
func (m *NATManager) Setup() error { return errNATUnsupported }

// Teardown is a no-op on non-Linux platforms.
func (m *NATManager) Teardown() error { return nil }

// NATCleanup always fails on non-Linux platforms.
func NATCleanup(_ []NATForward, _ NATOptions) error { return errNATUnsupported }
