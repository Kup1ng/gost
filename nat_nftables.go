package gost

import (
	"fmt"
	"strings"
)

// This file holds the PURE nftables ruleset generation (no netlink/exec), so it
// compiles and is unit-testable on every platform. The Linux-only backend that
// actually runs `nft` lives in nat_nftables_linux.go.

// nftTableName is the per-instance table, e.g. "gost_nat_1a2b3c4d". The hash is
// derived from the full -L set, so it is stable across restarts and unique
// across concurrent instances; cleanup is a single atomic `nft delete table`.
func nftTableName(forwards []NATForward) string {
	return natObjPrefix + "_" + instanceHash(forwards)
}

// nftRuleset renders the full nft document for `nft -f -`.
//
// A single-destination forward emits the proven plain-DNAT baseline. A forward
// with >= 2 destinations emits a weighted load-balancer:
//   - prerouting: `dnat to numgen inc mod N map { 0-2 : ip . port, 3 : ip . port }`
//     (numgen inc = strict weighted round-robin; the nat chain is traversed only
//     by the first/NEW packet of a flow, so it increments once per connection and
//     conntrack pins the flow to that backend for its whole life). Map keys cover
//     exactly 0..N-1 (N = sum of weights) by construction.
//   - postrouting/forward: a single rule each, scoped to the DNAT'd flows via an
//     anonymous concatenation set `ip daddr . proto dport { ip . port, ... }`.
//
// The chain is named "forward" (not "fwd") because `fwd` is a reserved nftables
// keyword. Map values use `ip . port` concatenation: `ip:port` is rejected
// inside an nft map. `dnat` is a terminal statement, so no trailing `counter`.
func nftRuleset(table string, forwards []NATForward, opts NATOptions) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "table ip %s {\n", table)

	// prerouting DNAT
	sb.WriteString("\tchain pre {\n")
	sb.WriteString("\t\ttype nat hook prerouting priority -100; policy accept;\n")
	for _, f := range forwards {
		sb.WriteString("\t\t")
		if !f.Wildcard() {
			fmt.Fprintf(&sb, "ip daddr %s ", f.BindAddr)
		}
		if f.single() {
			fmt.Fprintf(&sb, "%s dport %d dnat to %s comment \"%s\"\n",
				f.Proto, f.LPort, f.Dests[0].hostport(), f.comment())
		} else {
			m, n := nftWeightedMap(f.Dests)
			fmt.Fprintf(&sb, "%s dport %d dnat to numgen inc mod %d map { %s } comment \"%s\"\n",
				f.Proto, f.LPort, n, m, f.comment())
		}
	}
	sb.WriteString("\t}\n")

	// postrouting MASQUERADE, scoped to the DNAT'd flow only.
	sb.WriteString("\tchain post {\n")
	sb.WriteString("\t\ttype nat hook postrouting priority 100; policy accept;\n")
	if !opts.NoSNAT {
		for _, f := range forwards {
			if f.single() {
				d := f.Dests[0]
				fmt.Fprintf(&sb, "\t\tip daddr %s %s dport %d ct status dnat masquerade comment \"%s\"\n",
					d.IP.String(), f.Proto, d.Port, f.comment())
			} else {
				fmt.Fprintf(&sb, "\t\tip daddr . %s dport { %s } ct status dnat masquerade comment \"%s\"\n",
					f.Proto, nftConcatSet(f.Dests), f.comment())
			}
		}
	}
	sb.WriteString("\t}\n")

	// forward ACCEPT, scoped to the DNAT'd flow (both directions).
	if !opts.NoForwardRule {
		sb.WriteString("\tchain forward {\n")
		sb.WriteString("\t\ttype filter hook forward priority 0; policy accept;\n")
		for _, f := range forwards {
			if f.single() {
				d := f.Dests[0]
				fmt.Fprintf(&sb, "\t\tip daddr %s %s dport %d ct status dnat accept comment \"%s\"\n",
					d.IP.String(), f.Proto, d.Port, f.comment())
				fmt.Fprintf(&sb, "\t\tip saddr %s %s sport %d ct status dnat accept comment \"%s\"\n",
					d.IP.String(), f.Proto, d.Port, f.comment())
			} else {
				set := nftConcatSet(f.Dests)
				fmt.Fprintf(&sb, "\t\tip daddr . %s dport { %s } ct status dnat accept comment \"%s\"\n",
					f.Proto, set, f.comment())
				fmt.Fprintf(&sb, "\t\tip saddr . %s sport { %s } ct status dnat accept comment \"%s\"\n",
					f.Proto, set, f.comment())
			}
		}
		sb.WriteString("\t}\n")
	}

	sb.WriteString("}\n")
	return sb.String()
}

// nftWeightedMap renders the numgen map ("0-2 : 1.1.1.1 . 80, 3 : 2.2.2.2 . 80")
// and returns it along with N (= sum of weights = the numgen modulus). Keys
// cover exactly 0..N-1 by construction (cumulative contiguous ranges) — an
// uncovered key would silently leave those connections un-DNAT'd.
func nftWeightedMap(dests []NATDest) (string, int) {
	var b strings.Builder
	start := 0
	for i, d := range dests {
		if i > 0 {
			b.WriteString(", ")
		}
		if d.Weight == 1 {
			fmt.Fprintf(&b, "%d : %s . %d", start, d.IP.String(), d.Port)
		} else {
			fmt.Fprintf(&b, "%d-%d : %s . %d", start, start+d.Weight-1, d.IP.String(), d.Port)
		}
		start += d.Weight
	}
	return b.String(), start
}

// nftConcatSet renders a deduplicated "ip . port, ip . port" anonymous set for
// the masquerade/forward concatenation match.
func nftConcatSet(dests []NATDest) string {
	seen := make(map[string]bool, len(dests))
	var parts []string
	for _, d := range dests {
		k := fmt.Sprintf("%s . %d", d.IP.String(), d.Port)
		if !seen[k] {
			seen[k] = true
			parts = append(parts, k)
		}
	}
	return strings.Join(parts, ", ")
}
