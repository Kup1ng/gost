//go:build linux
// +build linux

package gost

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/go-log/log"
)

// iptablesBackend is the fallback programmer, used when nftables is not
// available. It keeps its rules in dedicated per-instance chains
// (GOST_<hash>_PRE / _POST / _FWD) jumped from the builtin chains, tagged with
// the composite comment so they can never be confused with anything else.
type iptablesBackend struct {
	ipt *iptables.IPTables
	err error
}

func newIptablesBackend() *iptablesBackend {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	return &iptablesBackend{ipt: ipt, err: err}
}

func (b *iptablesBackend) name() string { return "iptables" }

func (b *iptablesBackend) available() bool {
	if b.ipt == nil || b.err != nil {
		return false
	}
	_, err := b.ipt.ListChains("nat")
	return err == nil
}

func (b *iptablesBackend) chains(forwards []NATForward) (pre, post, fwd string) {
	base := "GOST_" + instanceHash(forwards)
	return base + "_PRE", base + "_POST", base + "_FWD"
}

func (b *iptablesBackend) program(forwards []NATForward, opts NATOptions) error {
	pre, post, fwd := b.chains(forwards)

	// Idempotent replace: scrub any leftover from a crashed run of the same set.
	_ = b.cleanup(forwards, opts)

	// nat: DNAT chain.
	if err := b.ipt.ClearChain("nat", pre); err != nil {
		return fmt.Errorf("create %s: %w", pre, err)
	}
	if err := b.ipt.AppendUnique("nat", "PREROUTING", "-j", pre); err != nil {
		return fmt.Errorf("jump PREROUTING->%s: %w", pre, err)
	}
	// nat: SNAT chain.
	if err := b.ipt.ClearChain("nat", post); err != nil {
		return fmt.Errorf("create %s: %w", post, err)
	}
	if err := b.ipt.AppendUnique("nat", "POSTROUTING", "-j", post); err != nil {
		return fmt.Errorf("jump POSTROUTING->%s: %w", post, err)
	}
	// filter: scoped FORWARD accept. Inserted at the top of FORWARD so the
	// scoped accept is reached before a restrictive ruleset can drop the flow.
	if !opts.NoForwardRule {
		if err := b.ipt.ClearChain("filter", fwd); err != nil {
			return fmt.Errorf("create %s: %w", fwd, err)
		}
		if err := b.ipt.Insert("filter", "FORWARD", 1, "-j", fwd); err != nil {
			return fmt.Errorf("jump FORWARD->%s: %w", fwd, err)
		}
	}

	for _, f := range forwards {
		tag := f.comment()
		dport := strconv.Itoa(f.LPort)

		// DNAT. A single destination is a plain DNAT. Multiple destinations are
		// weighted-RANDOM via the statistic module with CUMULATIVE conditional
		// probabilities (iptables has no strict weighted-nth mode; strict
		// weighted round-robin is the nftables `numgen inc` path). For each
		// backend except the last, probability = weight / (sum of remaining
		// weights); the last backend is the no-statistic catch-all and MUST be
		// appended last. Distribution is per-connection: PREROUTING DNAT is only
		// applied to the first/NEW packet of a flow (conntrack), so statistic
		// rolls once per connection and the flow then sticks to that backend.
		remaining := f.totalWeight()
		for i, d := range f.Dests {
			dnat := []string{"-p", f.Proto}
			if !f.Wildcard() {
				dnat = append(dnat, "-d", f.BindAddr)
			}
			dnat = append(dnat, "--dport", dport)
			if i < len(f.Dests)-1 {
				p := float64(d.Weight) / float64(remaining)
				dnat = append(dnat, "-m", "statistic", "--mode", "random",
					"--probability", strconv.FormatFloat(p, 'f', 6, 64))
			}
			dnat = append(dnat, "-m", "comment", "--comment", tag,
				"-j", "DNAT", "--to-destination", d.hostport())
			if err := b.ipt.Append("nat", pre, dnat...); err != nil {
				return fmt.Errorf("DNAT %s: %w", tag, err)
			}
			remaining -= d.Weight
		}

		// MASQUERADE + FORWARD accept: one (resp. two) rule(s) per backend,
		// each scoped to flows this table DNAT'd.
		for _, d := range f.Dests {
			ddest := d.IP.String()
			ddport := strconv.Itoa(d.Port)
			if !opts.NoSNAT {
				masq := []string{"-p", f.Proto, "-d", ddest, "--dport", ddport,
					"-m", "conntrack", "--ctstate", "DNAT",
					"-m", "comment", "--comment", tag, "-j", "MASQUERADE"}
				if err := b.ipt.Append("nat", post, masq...); err != nil {
					return fmt.Errorf("MASQUERADE %s: %w", tag, err)
				}
			}
			if !opts.NoForwardRule {
				out := []string{"-p", f.Proto, "-d", ddest, "--dport", ddport,
					"-m", "conntrack", "--ctstate", "DNAT",
					"-m", "comment", "--comment", tag, "-j", "ACCEPT"}
				ret := []string{"-p", f.Proto, "-s", ddest, "--sport", ddport,
					"-m", "conntrack", "--ctstate", "DNAT",
					"-m", "comment", "--comment", tag, "-j", "ACCEPT"}
				if err := b.ipt.Append("filter", fwd, out...); err != nil {
					return fmt.Errorf("FORWARD accept %s: %w", tag, err)
				}
				if err := b.ipt.Append("filter", fwd, ret...); err != nil {
					return fmt.Errorf("FORWARD return %s: %w", tag, err)
				}
			}
		}
	}
	return nil
}

func (b *iptablesBackend) cleanup(forwards []NATForward, _ NATOptions) error {
	pre, post, fwd := b.chains(forwards)
	b.delJumpAndChain("nat", "PREROUTING", pre)
	b.delJumpAndChain("nat", "POSTROUTING", post)
	b.delJumpAndChain("filter", "FORWARD", fwd)
	return nil
}

// rescue removes every GOST_* chain (and its jump) from the nat and filter
// tables, regardless of instance.
func (b *iptablesBackend) rescue() error {
	for table, parents := range map[string][]string{
		"nat":    {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"},
		"filter": {"INPUT", "FORWARD", "OUTPUT"},
	} {
		chains, err := b.ipt.ListChains(table)
		if err != nil {
			continue
		}
		for _, c := range chains {
			if !strings.HasPrefix(c, "GOST_") {
				continue
			}
			for _, p := range parents {
				_ = b.ipt.Delete(table, p, "-j", c)
			}
			_ = b.ipt.ClearChain(table, c)
			if err := b.ipt.DeleteChain(table, c); err == nil {
				log.Logf("[nat] removed iptables chain %s/%s", table, c)
			}
		}
	}
	return nil
}

// delJumpAndChain removes the jump from parent then flushes and deletes the
// chain. Best-effort: a chain can only be deleted once unreferenced and empty,
// so the order matters; individual errors are ignored (idempotent).
func (b *iptablesBackend) delJumpAndChain(table, parent, chain string) {
	_ = b.ipt.Delete(table, parent, "-j", chain)
	if !b.chainExists(table, chain) {
		return
	}
	_ = b.ipt.ClearChain(table, chain)
	_ = b.ipt.DeleteChain(table, chain)
}

func (b *iptablesBackend) chainExists(table, chain string) bool {
	chains, err := b.ipt.ListChains(table)
	if err != nil {
		return false
	}
	for _, c := range chains {
		if c == chain {
			return true
		}
	}
	return false
}
